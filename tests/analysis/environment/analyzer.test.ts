import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
    CommandError,
    EnvironmentAnalyzer,
    EnvironmentInputError,
    type CommandResult,
    type CommandRunner,
} from '../../../source/core/environment-analysis';

const fixture = (name: string) => readFileSync(join(__dirname, 'fixtures', name), 'utf8');
const ok = (stdout: string): CommandResult => ({ stdout, stderr: '', exitCode: 0 });

/** Answers per binary name; lynis writes its report to the --report-file path like the real tool. */
function fakeRunner(overrides: Record<string, (args: string[]) => CommandResult | Promise<CommandResult>> = {}) {
    const calls: Array<{ binary: string; args: string[]; timeoutMs: number }> = [];
    const defaults: Record<string, (args: string[]) => CommandResult> = {
        nmap: () => ok(fixture('nmap.xml')),
        httpx: () => ok(fixture('httpx.jsonl')),
        nuclei: () => ok(fixture('nuclei.jsonl')),
        trivy: () => ok(fixture('trivy.json')),
        lynis: args => {
            writeFileSync(args[args.indexOf('--report-file') + 1] as string, fixture('lynis.dat'));
            return ok('');
        },
    };
    const runner: CommandRunner = {
        async run(binary, args, { timeoutMs }) {
            calls.push({ binary, args, timeoutMs });
            const handler = overrides[binary] ?? defaults[binary];
            if (!handler) throw new Error(`unexpected binary ${binary}`);
            return handler(args);
        },
    };
    return { runner, calls };
}

const input = { tenantId: 'acme', projectPath: __dirname, targets: ['http://127.0.0.1:8099'], lynis: true };

describe('EnvironmentAnalyzer', () => {
    it('runs every tool and attributes each result', async () => {
        const result = await new EnvironmentAnalyzer(fakeRunner().runner, { privileged: false }).analyze(input);
        expect(result.tenantId).toBe('acme');
        for (const run of [result.nmap, result.nuclei, result.trivy, result.httpx, result.lynis]) {
            expect(run.status).toBe('ok');
        }
        expect(result.lynis).toMatchObject({ tool: 'lynis', result: { score: 65, privileged: false } });
    });

    it('records a missing tool and keeps the others (T28)', async () => {
        const { runner } = fakeRunner({
            trivy: () => {
                throw new CommandError('missing', 'trivy is not installed');
            },
        });
        const result = await new EnvironmentAnalyzer(runner).analyze(input);
        expect(result.trivy).toMatchObject({ status: 'failed', error: { kind: 'missing' } });
        expect(result.nmap.status).toBe('ok');
        expect(result.httpx.status).toBe('ok');
    });

    it('records a timeout, a bad exit code and unparsable output separately', async () => {
        const { runner } = fakeRunner({
            nmap: () => {
                throw new CommandError('timeout', 'nmap timed out');
            },
            nuclei: () => ({ stdout: '', stderr: 'boom', exitCode: 2 }),
            httpx: () => ok('not json'),
        });
        const result = await new EnvironmentAnalyzer(runner).analyze(input);
        expect(result.nmap).toMatchObject({ status: 'failed', error: { kind: 'timeout' } });
        expect(result.nuclei).toMatchObject({ status: 'failed', error: { kind: 'exit' } });
        expect(result.httpx).toMatchObject({ status: 'failed', error: { kind: 'parse' } });
    });

    it('skips tools whose input is missing', async () => {
        const { runner, calls } = fakeRunner();
        const result = await new EnvironmentAnalyzer(runner).analyze({ tenantId: 'acme', targets: [], lynis: false });
        expect(result.nmap.status).toBe('skipped');
        expect(result.nuclei.status).toBe('skipped');
        expect(result.httpx.status).toBe('skipped');
        expect(result.trivy.status).toBe('skipped');
        expect(result.lynis.status).toBe('skipped');
        expect(calls).toEqual([]);
    });

    it('gives nmap the host and the HTTP scanners the URL', async () => {
        const { runner, calls } = fakeRunner();
        await new EnvironmentAnalyzer(runner).analyze({ ...input, targets: ['http://127.0.0.1:8099', 'http://127.0.0.1:8099/'] });
        expect(calls.find(c => c.binary === 'nmap')?.args).toContain('127.0.0.1');
        expect(calls.find(c => c.binary === 'httpx')?.args.filter(a => a === '-u')).toHaveLength(1);
    });

    it.each([['-oX/tmp/x'], ['host name'], ['http://'], ['']])('rejects target %j before running anything', async target => {
        const { runner, calls } = fakeRunner();
        await expect(new EnvironmentAnalyzer(runner).analyze({ ...input, targets: [target] })).rejects.toThrow(EnvironmentInputError);
        expect(calls).toEqual([]);
    });

    it('rejects a relative projectPath and an invalid tenantId', async () => {
        const analyzer = new EnvironmentAnalyzer(fakeRunner().runner);
        await expect(analyzer.analyze({ ...input, projectPath: 'relative/dir' })).rejects.toThrow(EnvironmentInputError);
        await expect(analyzer.analyze({ ...input, tenantId: '../etc' })).rejects.toThrow(EnvironmentInputError);
    });

    it('applies per-analysis timeouts to the named tool only', async () => {
        const { runner, calls } = fakeRunner();
        await new EnvironmentAnalyzer(runner, { timeoutsMs: { nmap: 5_000 } }).analyze({
            ...input,
            timeoutsMs: { nuclei: 900_000 },
        });
        const timeout = (binary: string) => calls.find(c => c.binary === binary)?.timeoutMs;
        expect(timeout('nuclei')).toBe(900_000);
        expect(timeout('nmap')).toBe(5_000);
        expect(timeout('httpx')).toBe(2 * 60_000);
    });

    it('passes the nuclei rate limit only when given', async () => {
        const withLimit = fakeRunner();
        await new EnvironmentAnalyzer(withLimit.runner).analyze({ ...input, nucleiRateLimit: 50 });
        const args = withLimit.calls.find(c => c.binary === 'nuclei')?.args ?? [];
        expect(args.slice(args.indexOf('-rl'), args.indexOf('-rl') + 2)).toEqual(['-rl', '50']);

        const without = fakeRunner();
        await new EnvironmentAnalyzer(without.runner).analyze(input);
        expect(without.calls.find(c => c.binary === 'nuclei')?.args).not.toContain('-rl');
    });

    it.each([
        ['zero timeout', { timeoutsMs: { nuclei: 0 } }],
        ['negative timeout', { timeoutsMs: { nuclei: -5 } }],
        ['fractional timeout', { timeoutsMs: { nuclei: 1500.5 } }],
        ['timeout over 2h', { timeoutsMs: { nuclei: 3 * 60 * 60_000 } }],
        ['unknown tool', { timeoutsMs: { nikto: 5_000 } }],
        ['zero rate limit', { nucleiRateLimit: 0 }],
        ['fractional rate limit', { nucleiRateLimit: 2.5 }],
        ['huge rate limit', { nucleiRateLimit: 100_000 }],
    ])('rejects %s before running anything', async (_name, extra) => {
        const { runner, calls } = fakeRunner();
        await expect(new EnvironmentAnalyzer(runner).analyze({ ...input, ...extra } as typeof input)).rejects.toThrow(EnvironmentInputError);
        expect(calls).toEqual([]);
    });
});
