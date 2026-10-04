/**
 * Scores the 100 labeled cases in tests/fixtures/jev-cases.json through the real static pipeline (every tool),
 * then JEV, and reports how well the attack probability and the threshold separate attacks from benign requests.
 * Needs TYPESAFE_API_KEY. Not part of CI; the offline fixture checks are in tests/fixtures/jevCases.test.ts.
 *
 *   npm run eval:jev                          # direct: static pipeline + JevClient in-process
 *   npm run eval:jev -- --http                # real HTTP: in-process Tessera gateway -> mock upstream
 *   npm run eval:jev -- --threshold 0.6 --category attack/sqli --runs 3
 *   npm run eval:jev -- --out runs/a.json     # save, then:  --compare runs/a.json runs/b.json
 *
 * Tune the question wording and thresholds against the whole set, never against a single case.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { TypeSafeClient } from '@typesafe-ai/sdk';
import { JevClient } from '../source/core/jev/client';
import {
    expandValue,
    loadFixture,
    runStatic,
    splitEndpoint,
    defaultClientIp,
    type EvalCase,
    type Fixture,
} from '../tests/fixtures/jevCases';
import { startGateway } from './eval-gateway';
import { startMockUpstream } from './mock-upstream';

interface Row {
    name: string;
    label: 'attack' | 'benign';
    category: string;
    endpoint: string;
    static: string;
    hits: string[];
    decidedBy: 'static' | 'jev' | 'error' | 'skipped';
    p?: number;
    severity?: number;
    /** Max minus min attack probability across --runs. */
    spread?: number;
    note?: string;
}

interface Saved {
    threshold: number;
    runs: number;
    mode: 'direct' | 'http';
    rows: Row[];
}

const SWEEP = Array.from({ length: 13 }, (_, i) => Math.round((0.3 + i * 0.05) * 100) / 100);

function arg(name: string): string | undefined {
    const index = process.argv.indexOf(`--${name}`);
    return index >= 0 ? process.argv[index + 1] : undefined;
}
const flag = (name: string) => process.argv.includes(`--${name}`);

async function pool<T, R>(items: T[], size: number, work: (item: T, index: number) => Promise<R>): Promise<R[]> {
    const results = new Array<R>(items.length);
    let next = 0;
    await Promise.all(
        Array.from({ length: Math.min(size, items.length) }, async () => {
            while (next < items.length) {
                const index = next++;
                results[index] = await work(items[index], index);
            }
        })
    );
    return results;
}

const base = (c: EvalCase) => ({ name: c.name, label: c.label, category: c.category, endpoint: c.endpoint });
const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error));

async function evalDirect(c: EvalCase, index: number, fixture: Fixture, jev: JevClient, runs: number): Promise<Row> {
    const outcome = runStatic(c, index, fixture);
    const common = { ...base(c), static: outcome.verdict.verdict, hits: outcome.hits };
    if (outcome.verdict.verdict === 'POLICY_VIOLATION') return { ...common, decidedBy: 'static' };
    if (outcome.verdict.verdict === 'ERROR') return { ...common, decidedBy: 'error', note: 'static analysis error' };

    try {
        const verdicts = [];
        for (let i = 0; i < runs; i++) verdicts.push(await jev.createVerdict(outcome.request, outcome.verdict));
        const ps = verdicts.map((v) => v.attackProbability);
        return {
            ...common,
            decidedBy: 'jev',
            p: ps.reduce((a, b) => a + b, 0) / runs,
            severity: verdicts.reduce((a, v) => a + v.score, 0) / runs,
            spread: Math.max(...ps) - Math.min(...ps),
        };
    } catch (error) {
        return { ...common, decidedBy: 'error', note: `JEV failed: ${errorMessage(error)}` };
    }
}

async function evalHttp(c: EvalCase, index: number, gatewayUrl: string): Promise<Row> {
    if (c.files?.length) return { ...base(c), static: '-', hits: [], decidedBy: 'skipped', note: 'file uploads are not sent over the mock HTTP path' };

    const { method, path } = splitEndpoint(c.endpoint);
    const query = Object.entries(c.query ?? {}).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    const url = `${gatewayUrl}${path}${query ? `?${query}` : ''}`;
    const hasBody = c.body !== undefined && method !== 'GET';

    let response!: Response;
    for (let attempt = 0; attempt < (c.repeat ?? 1); attempt++) {
        response = await fetch(url, {
            method,
            headers: { 'content-type': 'application/json', 'x-forwarded-for': c.clientIp ?? defaultClientIp(index) },
            body: hasBody ? JSON.stringify(expandValue(c.body)) : undefined,
        });
        if (attempt < (c.repeat ?? 1) - 1) await response.arrayBuffer();
    }

    const staticVerdict = response.headers.get('x-tessera-static') ?? '?';
    const reason = response.headers.get('x-tessera-reason') ?? '';
    const p = response.headers.get('x-tessera-p');
    const common = { ...base(c), static: staticVerdict, hits: [] as string[] };
    const blocked = response.status === 403;

    // Fastify's JSON parser refuses bodies such as a "__proto__" key before any Tessera code runs; nothing is forwarded.
    if (response.status === 400 && staticVerdict === '?') return { ...common, decidedBy: 'static', note: 'rejected by the body parser (400) before analysis' };
    if (!blocked && response.status >= 300) return { ...common, decidedBy: 'error', note: `upstream status ${response.status}` };
    if (p !== null) {
        return { ...common, decidedBy: 'jev', p: Number(p), severity: Number(response.headers.get('x-tessera-severity')) };
    }
    if (/unavailable|invalid|error/.test(reason)) return { ...common, decidedBy: 'error', note: reason };
    return { ...common, decidedBy: 'static', note: blocked ? reason : 'allowed without JEV' };
}

// ---------- metrics

const blockedAt = (row: Row, t: number) => row.decidedBy === 'static' ? true : (row.p as number) > t;

function auc(rows: Row[]): number {
    const attacks = rows.filter((r) => r.label === 'attack').map((r) => r.p as number);
    const benign = rows.filter((r) => r.label === 'benign').map((r) => r.p as number);
    const pairs = attacks.flatMap((a) => benign.map((b) => (a > b ? 1 : a === b ? 0.5 : 0)));
    return pairs.length ? pairs.reduce<number>((s, x) => s + x, 0) / pairs.length : NaN;
}

function confusion(rows: Row[], t: number) {
    const scored = rows.filter((r) => r.decidedBy === 'static' || r.decidedBy === 'jev');
    const tp = scored.filter((r) => r.label === 'attack' && blockedAt(r, t)).length;
    const fn = scored.filter((r) => r.label === 'attack' && !blockedAt(r, t)).length;
    const fp = scored.filter((r) => r.label === 'benign' && blockedAt(r, t)).length;
    const tn = scored.filter((r) => r.label === 'benign' && !blockedAt(r, t)).length;
    const precision = tp + fp ? tp / (tp + fp) : 1;
    const recall = tp + fn ? tp / (tp + fn) : 1;
    return { tp, fn, fp, tn, f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0 };
}

const pct = (n: number, d: number) => (d ? `${Math.round((100 * n) / d)}%` : '-');
const fmt = (p?: number) => (p === undefined ? '  -  ' : p.toFixed(3));

function report(saved: Saved): void {
    const { rows, threshold } = saved;
    const jevRows = rows.filter((r) => r.decidedBy === 'jev');

    console.log(`\n=== cases (decision at threshold ${threshold}) ===`);
    let lastCategory = '';
    for (const r of [...rows].sort((a, b) => a.category.localeCompare(b.category))) {
        if (r.category !== lastCategory) console.log(`\n[${(lastCategory = r.category)}]`);
        const decided = r.decidedBy === 'error' || r.decidedBy === 'skipped' ? r.decidedBy.toUpperCase() : blockedAt(r, threshold) ? 'BLOCK' : 'ALLOW';
        const wrong = (r.decidedBy === 'static' || r.decidedBy === 'jev') && (decided === 'BLOCK') !== (r.label === 'attack');
        const spread = r.spread !== undefined && r.spread > 0 ? ` ±${(r.spread / 2).toFixed(2)}` : '';
        console.log(
            `${wrong ? '✗' : r.decidedBy === 'error' || r.decidedBy === 'skipped' ? '?' : '✓'} ${decided.padEnd(5)} p=${fmt(r.p)}${spread.padEnd(6)} ` +
                `${r.static.padEnd(16)} ${r.name}${r.hits.length ? `  [${r.hits.join(' ')}]` : ''}${r.note ? `  (${r.note})` : ''}`
        );
    }

    const kinds = (decidedBy: Row['decidedBy']) => rows.filter((r) => r.decidedBy === decidedBy).length;
    console.log(`\n=== coverage ===\n${rows.length} cases: ${kinds('jev')} scored by JEV, ${kinds('static')} blocked statically, ${kinds('error')} errors, ${kinds('skipped')} skipped`);

    console.log('\n=== static tools ===');
    const benign = rows.filter((r) => r.label === 'benign' && r.static !== '-');
    const attacks = rows.filter((r) => r.label === 'attack' && r.static !== '-');
    const count = (list: Row[], verdict: string) => list.filter((r) => r.static === verdict).length;
    console.log(`benign:  ${count(benign, 'SAFE')} SAFE, ${count(benign, 'SUSPICIOUS')} SUSPICIOUS (extra JEV calls), ${count(benign, 'POLICY_VIOLATION')} wrongly blocked`);
    console.log(`attacks: ${count(attacks, 'POLICY_VIOLATION')} blocked, ${count(attacks, 'SUSPICIOUS')} flagged for JEV, ${count(attacks, 'SAFE')} missed by the tools (JEV only)`);

    console.log('\n=== JEV threshold sweep (JEV-scored cases only | whole pipeline incl. static blocks) ===');
    console.log('threshold   JEV fp  JEV fn |  all fp  all fn   F1');
    for (const t of SWEEP) {
        const jevFp = jevRows.filter((r) => r.label === 'benign' && (r.p as number) > t).length;
        const jevFn = jevRows.filter((r) => r.label === 'attack' && (r.p as number) <= t).length;
        const all = confusion(rows, t);
        console.log(`${t.toFixed(2).padStart(9)} ${String(jevFp).padStart(8)} ${String(jevFn).padStart(7)} | ${String(all.fp).padStart(7)} ${String(all.fn).padStart(7)}  ${all.f1.toFixed(3)}${t === threshold ? '  <- current' : ''}`);
    }
    const best = SWEEP.map((t) => ({ t, ...confusion(rows, t) })).sort((a, b) => b.f1 - a.f1 || b.t - a.t)[0];
    const noFp = SWEEP.find((t) => confusion(rows, t).fp === 0);
    console.log(`AUC (JEV-scored) ${auc(jevRows).toFixed(3)}  |  best F1 ${best.f1.toFixed(3)} at ${best.t.toFixed(2)}  |  lowest threshold with no false positives: ${noFp ?? 'none in range'}`);

    console.log('\n=== hardest cases (JEV-scored) ===');
    const hardBenign = jevRows.filter((r) => r.label === 'benign').sort((a, b) => (b.p as number) - (a.p as number)).slice(0, 10);
    const hardAttacks = jevRows.filter((r) => r.label === 'attack').sort((a, b) => (a.p as number) - (b.p as number)).slice(0, 10);
    console.log('benign scored highest:');
    hardBenign.forEach((r) => console.log(`  p=${fmt(r.p)}  ${r.name}`));
    console.log('attacks scored lowest:');
    hardAttacks.forEach((r) => console.log(`  p=${fmt(r.p)}  ${r.name}`));

    console.log('\n=== by category at the current threshold ===');
    for (const category of [...new Set(rows.map((r) => r.category))].sort()) {
        const inCategory = rows.filter((r) => r.category === category && (r.decidedBy === 'jev' || r.decidedBy === 'static'));
        const wrong = inCategory.filter((r) => blockedAt(r, threshold) !== (r.label === 'attack')).length;
        const ps = inCategory.filter((r) => r.p !== undefined).map((r) => r.p as number);
        const mean = ps.length ? (ps.reduce((a, b) => a + b, 0) / ps.length).toFixed(2) : '  - ';
        console.log(`${category.padEnd(34)} n=${String(inCategory.length).padStart(2)}  mean p=${mean}  wrong=${wrong}`);
    }

    const noisy = jevRows.filter((r) => (r.spread ?? 0) > 0.1);
    if (saved.runs > 1) console.log(`\n=== JEV noise over ${saved.runs} runs ===\n${noisy.length} cases moved by more than 0.1: ${noisy.map((r) => r.name).join(', ') || 'none'}`);
}

function compare(aPath: string, bPath: string): void {
    const a: Saved = JSON.parse(readFileSync(aPath, 'utf8'));
    const b: Saved = JSON.parse(readFileSync(bPath, 'utf8'));
    const byName = new Map(b.rows.map((r) => [r.name, r]));

    console.log(`A = ${aPath}\nB = ${bPath}\n`);
    console.log(`AUC            A ${auc(a.rows.filter((r) => r.decidedBy === 'jev')).toFixed(3)}   B ${auc(b.rows.filter((r) => r.decidedBy === 'jev')).toFixed(3)}`);
    console.log('threshold  A fp/fn   B fp/fn');
    for (const t of [0.5, 0.6, 0.7, 0.8, 0.9]) {
        const ca = confusion(a.rows, t);
        const cb = confusion(b.rows, t);
        console.log(`${t.toFixed(2).padStart(9)}  ${String(ca.fp).padStart(3)}/${String(ca.fn).padEnd(3)}    ${String(cb.fp).padStart(3)}/${String(cb.fn).padEnd(3)}`);
    }

    const moved = a.rows
        .map((row) => ({ row, other: byName.get(row.name) }))
        .filter(({ row, other }) => row.p !== undefined && other?.p !== undefined && Math.abs(row.p - other.p) > 0.15)
        .sort((x, y) => Math.abs((y.other!.p as number) - (y.row.p as number)) - Math.abs((x.other!.p as number) - (x.row.p as number)));
    console.log(`\ncases whose p moved by more than 0.15 (${moved.length}):`);
    for (const { row, other } of moved) {
        const better = (other!.p as number) > (row.p as number) === (row.label === 'attack');
        console.log(`  ${better ? '↑ better' : '↓ worse '} ${row.label.padEnd(6)} ${fmt(row.p)} -> ${fmt(other!.p)}  ${row.name}`);
    }
}

/** Runs `work` with console.log silenced, so debug logging inside the code under test cannot bury the report. */
async function quietly<T>(work: () => Promise<T>): Promise<T> {
    const original = console.log;
    console.log = () => undefined;
    try {
        return await work();
    } finally {
        console.log = original;
    }
}

async function main(): Promise<void> {
    const compareIndex = process.argv.indexOf('--compare');
    if (compareIndex >= 0) return compare(process.argv[compareIndex + 1], process.argv[compareIndex + 2]);

    const threshold = Number(arg('threshold') ?? 0.7);
    const runs = Math.max(1, Number(arg('runs') ?? 1));
    const category = arg('category');
    const http = flag('http');
    const fixture = loadFixture();
    const selected = fixture.cases.map((c, index) => ({ c, index })).filter(({ c }) => !category || c.category.startsWith(category));
    if (selected.length === 0) throw new Error(`No case matches category "${category}"`);

    let rows: Row[];
    if (http) {
        if (runs > 1) console.warn('--runs is only used in direct mode; sending each case once.');
        const upstream = await startMockUpstream();
        const gateway = await startGateway({ upstreamUrl: upstream.url, fixture, threshold, adaptive: flag('adaptive') });
        console.log(`mock upstream ${upstream.url}, gateway ${gateway.url}`);
        try {
            rows = await quietly(() => pool(selected, 5, ({ c, index }) => evalHttp(c, index, gateway.url)));
        } finally {
            await gateway.app.close();
            await upstream.app.close();
        }
    } else {
        // No verdict cache: repeated runs must each reach JEV.
        const jev = new JevClient(new TypeSafeClient({}), { get: async () => null, set: async () => {} });
        rows = await quietly(() => pool(selected, 5, ({ c, index }) => evalDirect(c, index, fixture, jev, runs)));
    }

    const saved: Saved = { threshold, runs, mode: http ? 'http' : 'direct', rows };
    report(saved);

    const out = arg('out');
    if (out) {
        mkdirSync(dirname(out), { recursive: true });
        writeFileSync(out, JSON.stringify(saved, null, 2));
        console.log(`\nsaved ${out}`);
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
