/**
 * Runs EnvironmentAnalyzer against canned tool output instead of the real binaries.
 * Instant and needs none of nmap/nuclei/trivy/httpx/lynis installed.
 *
 *   npm run analyze:mock
 *   npm run analyze:mock -- --fail trivy,nmap   # make these tools report as missing
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CommandError, EnvironmentAnalyzer, type CommandRunner } from '../source/analysis/environment';

const fixtures = join(__dirname, '..', 'tests', 'analysis', 'environment', 'fixtures');
const fixture = (name: string) => readFileSync(join(fixtures, name), 'utf8');

const failIndex = process.argv.indexOf('--fail');
const failing = new Set((failIndex >= 0 ? process.argv[failIndex + 1] ?? '' : '').split(',').filter(Boolean));

const output: Record<string, string> = {
    nmap: 'nmap.xml',
    httpx: 'httpx.jsonl',
    nuclei: 'nuclei.jsonl',
    trivy: 'trivy.json',
};

const runner: CommandRunner = {
    async run(binary, args) {
        if (failing.has(binary)) throw new CommandError('missing', `${binary} is not installed (mock)`);
        if (binary === 'lynis') {
            // Like the real tool, Lynis writes its report to the --report-file path.
            writeFileSync(args[args.indexOf('--report-file') + 1] as string, fixture('lynis.dat'));
            return { stdout: '', stderr: '', exitCode: 0 };
        }
        const file = output[binary];
        if (!file) throw new Error(`no mock output for ${binary}`);
        return { stdout: fixture(file), stderr: '', exitCode: 0 };
    },
};

(async () => {
    const result = await new EnvironmentAnalyzer(runner, { privileged: false }).analyze({
        tenantId: 'mock',
        projectPath: process.cwd(),
        targets: ['http://127.0.0.1:8099'],
        lynis: true,
    });
    console.log(JSON.stringify(result, null, 2));
})();
