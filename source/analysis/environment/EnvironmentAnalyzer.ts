import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { CommandError, type CommandRunner } from './CommandRunner';
import { httpxArgs, parseHttpx } from './tools/httpx';
import { lynisArgs, parseLynis } from './tools/lynis';
import { nmapArgs, parseNmap } from './tools/nmap';
import { nucleiArgs, parseNuclei } from './tools/nuclei';
import { parseTrivy, trivyArgs } from './tools/trivy';
import type {
    EnvironmentAnalysisInput,
    EnvironmentAnalysisResult,
    EnvironmentTool,
    ToolRun,
} from './types';

export interface EnvironmentAnalyzerOptions {
    /** Binary names or paths per tool; defaults to the tool's own name. */
    binaries?: Partial<Record<EnvironmentTool, string>>;
    timeoutsMs?: Partial<Record<EnvironmentTool, number>>;
    /** Whether the process runs as root, which decides how complete a Lynis audit is. */
    privileged?: boolean;
}

/** The input itself is invalid, as opposed to a tool failing, which is recorded in the result. */
export class EnvironmentInputError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'EnvironmentInputError';
    }
}

const DEFAULT_TIMEOUTS_MS: Record<EnvironmentTool, number> = {
    nmap: 5 * 60_000,
    nuclei: 30 * 60_000,
    trivy: 2 * 60_000,
    httpx: 2 * 60_000,
    lynis: 5 * 60_000,
};

const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 2 * 60 * 60_000;
const MAX_RATE_LIMIT = 1_000;
const TENANT_ID = /^[A-Za-z0-9_-]{1,40}$/;
const HOSTNAME = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

interface Targets {
    /** Full URLs or bare hosts for the HTTP scanners. */
    urls: string[];
    /** Deduplicated hosts for nmap. */
    hosts: string[];
}

/**
 * Collects environment context with nmap, nuclei, trivy, httpx and lynis.
 *
 * Runs in the collector, inside the customer's environment. A failing or missing tool never fails
 * the analysis: it is recorded as a `failed` run and the other tools still report.
 *
 * Targets are only checked for format, not restricted: nuclei sends active payloads, so callers
 * must only pass hosts the customer owns.
 */
export class EnvironmentAnalyzer {
    private readonly binaries: Record<EnvironmentTool, string>;
    private readonly timeoutsMs: Record<EnvironmentTool, number>;
    private readonly privileged: boolean;

    constructor(
        private readonly runner: CommandRunner,
        options: EnvironmentAnalyzerOptions = {}
    ) {
        this.binaries = { nmap: 'nmap', nuclei: 'nuclei', trivy: 'trivy', httpx: 'httpx', lynis: 'lynis', ...options.binaries };
        this.timeoutsMs = { ...DEFAULT_TIMEOUTS_MS, ...options.timeoutsMs };
        this.privileged = options.privileged ?? process.getuid?.() === 0;
    }

    async analyze(input: EnvironmentAnalysisInput): Promise<EnvironmentAnalysisResult> {
        if (!TENANT_ID.test(input.tenantId)) throw new EnvironmentInputError('invalid tenantId');
        const targets = parseTargets(input.targets);
        if (input.projectPath !== undefined) await assertProjectDirectory(input.projectPath);
        const timeoutsMs = this.resolveTimeouts(input.timeoutsMs);
        const rateLimit = input.nucleiRateLimit;
        if (rateLimit !== undefined && !isIntegerInRange(rateLimit, 1, MAX_RATE_LIMIT)) {
            throw new EnvironmentInputError(`nucleiRateLimit must be an integer from 1 to ${MAX_RATE_LIMIT}`);
        }

        const startedAt = new Date().toISOString();
        const noTargets = targets.urls.length === 0 ? 'no targets given' : undefined;
        const [nmap, nuclei, trivy, httpx, lynis] = await Promise.all([
            this.track('nmap', noTargets, async () => parseNmap(await this.exec('nmap', nmapArgs(targets.hosts), timeoutsMs.nmap))),
            this.track('nuclei', noTargets, async () => parseNuclei(await this.exec('nuclei', nucleiArgs(targets.urls, rateLimit), timeoutsMs.nuclei))),
            this.track(
                'trivy',
                input.projectPath === undefined ? 'no projectPath given' : undefined,
                async () => parseTrivy(await this.exec('trivy', trivyArgs(input.projectPath as string), timeoutsMs.trivy))
            ),
            this.track('httpx', noTargets, async () => parseHttpx(await this.exec('httpx', httpxArgs(targets.urls), timeoutsMs.httpx))),
            this.track('lynis', input.lynis ? undefined : 'lynis not requested', () => this.runLynis(timeoutsMs.lynis)),
        ]);

        return { tenantId: input.tenantId, startedAt, completedAt: new Date().toISOString(), nmap, nuclei, trivy, httpx, lynis };
    }

    private async runLynis(timeoutMs: number) {
        const dir = await mkdtemp(join(tmpdir(), 'tessera-lynis-'));
        try {
            const reportFile = join(dir, 'report.dat');
            await this.exec('lynis', lynisArgs(reportFile), timeoutMs);
            return parseLynis(await readFile(reportFile, 'utf8'), this.privileged);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    }

    private resolveTimeouts(overrides: EnvironmentAnalysisInput['timeoutsMs'] = {}): Record<EnvironmentTool, number> {
        const merged = { ...this.timeoutsMs };
        for (const [tool, value] of Object.entries(overrides) as Array<[EnvironmentTool, number | undefined]>) {
            if (!(tool in merged)) throw new EnvironmentInputError(`unknown tool in timeoutsMs: ${tool}`);
            if (value === undefined) continue;
            if (!isIntegerInRange(value, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)) {
                throw new EnvironmentInputError(`timeoutsMs.${tool} must be an integer from ${MIN_TIMEOUT_MS} to ${MAX_TIMEOUT_MS}`);
            }
            merged[tool] = value;
        }
        return merged;
    }

    private async exec(tool: EnvironmentTool, args: string[], timeoutMs: number): Promise<string> {
        const { stdout, stderr, exitCode } = await this.runner.run(this.binaries[tool], args, { timeoutMs });
        if (exitCode !== 0) {
            throw new CommandError('exit', `${tool} exited with code ${exitCode}: ${stderr.trim().slice(0, 500)}`);
        }
        return stdout;
    }

    /** Runs one tool and converts every outcome, including a throw, into a ToolRun. Never rejects. */
    private async track<T>(tool: EnvironmentTool, skipReason: string | undefined, run: () => Promise<T>): Promise<ToolRun<T>> {
        const started = Date.now();
        const base = () => ({ tool, startedAt: new Date(started).toISOString(), durationMs: Date.now() - started });
        if (skipReason !== undefined) return { ...base(), status: 'skipped', reason: skipReason };
        try {
            const result = await run();
            return { ...base(), status: 'ok', result };
        } catch (error) {
            const kind = error instanceof CommandError ? error.kind : 'parse';
            const message = error instanceof Error ? error.message : String(error);
            return { ...base(), status: 'failed', error: { kind, message } };
        }
    }
}

function isIntegerInRange(value: number, min: number, max: number): boolean {
    return Number.isInteger(value) && value >= min && value <= max;
}

function parseTargets(targets: string[]): Targets {
    const urls = new Set<string>();
    const hosts = new Set<string>();
    for (const target of targets) {
        if (/^https?:\/\//i.test(target)) {
            let url: URL;
            try {
                url = new URL(target);
            } catch {
                throw new EnvironmentInputError(`invalid target URL: ${target}`);
            }
            urls.add(url.href);
            hosts.add(url.hostname.replace(/^\[|\]$/g, ''));
        } else if (isIP(target) !== 0 || HOSTNAME.test(target)) {
            // Anchored patterns above also reject a leading "-", so a target can never become a flag.
            urls.add(target);
            hosts.add(target);
        } else {
            throw new EnvironmentInputError(`invalid target: ${target}`);
        }
    }
    return { urls: [...urls], hosts: [...hosts] };
}

async function assertProjectDirectory(path: string): Promise<void> {
    if (!isAbsolute(path)) throw new EnvironmentInputError('projectPath must be absolute');
    const info = await stat(path).catch(() => undefined);
    if (!info?.isDirectory()) throw new EnvironmentInputError('projectPath is not a directory');
}
