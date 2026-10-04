import { describe, expect, it, vi } from 'vitest';
import { DecisionOrchestrator, type DecisionConfig, type RuntimeConfig } from '../../source/core/decisionOrchestrator';
import { Sampler } from '../../source/core/sampling';
import { AdaptiveControl } from '../../source/feedback';
import type { DynamicVerdict } from '../../source/core/jev/client';
import type { StaticVerdict } from '../../source/core/static-analysis/aggregator';
import type { NormalizedRequest } from '../../source/shared/contracts';

const TENANT = '3f2b8c1e4a5d4e6f8a7b9c0d';
const OTHER_TENANT = '7a1b2c3d4e5f4a6b9c8d0e1f';
const LOGIN = 'POST /login';

const ATTACK: DynamicVerdict = { score: 2.5, attackProbability: 0.95, confidence: 0.9 };
const BENIGN: DynamicVerdict = { score: 0.2, attackProbability: 0.05, confidence: 0.9 };
/** Below the user threshold, but above the floor it tightens to under attack. */
const BORDERLINE: DynamicVerdict = { score: 1.5, attackProbability: 0.6, confidence: 0.2 };

const RUNTIME: RuntimeConfig = {
    sampling: { probabilityN: 0.1, minN: 0.01, maxN: 1 },
    threshold: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false },
};

const CONFIG: DecisionConfig = {
    staticAnalysisError: 'BLOCK',
    suspiciousWhenJevUnavailable: 'BLOCK',
    sampledWhenJevUnavailable: 'ALLOW',
};

const request = (tenantId = TENANT, endpoint = LOGIN): NormalizedRequest => ({
    requestId: 'request-1',
    tenantId,
    endpoint,
    clientIp: '203.0.113.7',
    query: {},
    headers: {},
    body: {},
    requestHash: 'hash',
    fields: [],
    files: [],
    timestamp: 0,
});

const verdict = (kind: StaticVerdict['verdict']): StaticVerdict => ({ verdict: kind, results: [], evidence: undefined });

const jevDown = async (): Promise<DynamicVerdict> => {
    throw new Error('JEV down');
};

/** Real AdaptiveControl, spied, with a sampler forced to the given outcome. */
function setup({
    jev = async () => BENIGN,
    sampled = true,
    config = {},
}: { jev?: () => Promise<DynamicVerdict>; sampled?: boolean; config?: Partial<DecisionConfig> } = {}) {
    const adaptive = new AdaptiveControl();
    const observe = vi.spyOn(adaptive, 'observe');
    const createVerdict = vi.fn(jev);
    const shouldSample = vi.fn(() => sampled);
    const orchestrator = new DecisionOrchestrator(
        { jev: { createVerdict }, adaptive, sampler: { shouldSample }, configFor: () => RUNTIME },
        { ...CONFIG, ...config }
    );
    return { orchestrator, adaptive, createVerdict, shouldSample, observe };
}

describe('DecisionOrchestrator', () => {
    describe('static verdicts that never reach JEV', () => {
        it('blocks a policy violation without sampling, JEV or feedback', async () => {
            const t = setup();

            const decision = await t.orchestrator.orchestrate(request(), verdict('POLICY_VIOLATION'));

            expect(decision).toMatchObject({ action: 'BLOCK', sampled: false });
            expect(t.shouldSample).not.toHaveBeenCalled();
            expect(t.createVerdict).not.toHaveBeenCalled();
            expect(t.observe).not.toHaveBeenCalled();
        });

        it.each(['ALLOW', 'BLOCK'] as const)('applies the configured %s on a static analysis error', async action => {
            const t = setup({ config: { staticAnalysisError: action } });

            const decision = await t.orchestrator.orchestrate(request(), verdict('ERROR'));

            expect(decision.action).toBe(action);
            expect(t.createVerdict).not.toHaveBeenCalled();
            expect(t.observe).not.toHaveBeenCalled();
        });

        it('allows a SAFE request the sampler skips and records it as unsampled', async () => {
            const t = setup({ sampled: false });

            const decision = await t.orchestrator.orchestrate(request(), verdict('SAFE'));

            expect(decision).toMatchObject({ action: 'ALLOW', sampled: false });
            expect(t.createVerdict).not.toHaveBeenCalled();
            expect(t.observe).toHaveBeenCalledWith(TENANT, LOGIN, 'UNSAMPLED');
        });
    });

    describe('sampled SAFE requests', () => {
        it('draws with the adaptive N for the tenant and endpoint', async () => {
            const t = setup();

            await t.orchestrator.orchestrate(request(), verdict('SAFE'));

            expect(t.shouldSample).toHaveBeenCalledWith('SAFE', expect.closeTo(0.1, 5));
        });

        it('blocks an attack and feeds ATTACK back', async () => {
            const t = setup({ jev: async () => ATTACK });

            const decision = await t.orchestrator.orchestrate(request(), verdict('SAFE'));

            expect(decision).toMatchObject({
                action: 'BLOCK',
                sampled: true,
                jev: { ...ATTACK, verdict: 'ATTACK', threshold: 0.7 },
            });
            expect(t.observe).toHaveBeenCalledWith(TENANT, LOGIN, 'ATTACK');
        });

        it('allows a benign result and feeds BENIGN back', async () => {
            const t = setup({ jev: async () => BENIGN });

            const decision = await t.orchestrator.orchestrate(request(), verdict('SAFE'));

            expect(decision).toMatchObject({ action: 'ALLOW', sampled: true, jev: { ...BENIGN, verdict: 'BENIGN' } });
            expect(t.observe).toHaveBeenCalledWith(TENANT, LOGIN, 'BENIGN');
        });

        it.each(['ALLOW', 'BLOCK'] as const)(
            'applies the configured %s when JEV fails, and feeds nothing back',
            async action => {
                const t = setup({ jev: jevDown, config: { sampledWhenJevUnavailable: action } });

                const decision = await t.orchestrator.orchestrate(request(), verdict('SAFE'));

                expect(decision).toMatchObject({ action, sampled: true, reason: 'sampled and JEV unavailable' });
                expect(t.observe).not.toHaveBeenCalled();
            }
        );
    });

    describe('suspicious requests', () => {
        it('always go to JEV and never draw a sample', async () => {
            const t = setup({ sampled: false });

            const decision = await t.orchestrator.orchestrate(request(), verdict('SUSPICIOUS'));

            expect(t.shouldSample).not.toHaveBeenCalled();
            expect(t.createVerdict).toHaveBeenCalledOnce();
            expect(decision.sampled).toBe(false);
        });

        it('are allowed when the attack probability is below the threshold', async () => {
            const t = setup({ jev: async () => BORDERLINE });

            const decision = await t.orchestrator.orchestrate(request(), verdict('SUSPICIOUS'));

            expect(decision).toMatchObject({
                action: 'ALLOW',
                reason: 'JEV did not classify as attack (p=0.60, threshold=0.70)',
                jev: { verdict: 'BENIGN' },
            });
            expect(t.observe).toHaveBeenCalledWith(TENANT, LOGIN, 'BENIGN');
        });

        it.each(['ALLOW', 'BLOCK'] as const)(
            'apply the configured %s when JEV fails, and feed nothing back',
            async action => {
                const t = setup({ jev: jevDown, config: { suspiciousWhenJevUnavailable: action } });

                const decision = await t.orchestrator.orchestrate(request(), verdict('SUSPICIOUS'));

                expect(decision).toMatchObject({ action, reason: 'suspicious and JEV unavailable' });
                expect(t.observe).not.toHaveBeenCalled();
            }
        );

        it.each(['ALLOW', 'BLOCK'] as const)(
            'treat a malformed JEV result like a failure and apply the configured %s',
            async action => {
                const t = setup({
                    jev: async () => ({ score: 1, attackProbability: NaN, confidence: NaN }),
                    config: { suspiciousWhenJevUnavailable: action },
                });

                const decision = await t.orchestrator.orchestrate(request(), verdict('SUSPICIOUS'));

                expect(decision).toMatchObject({ action, reason: 'suspicious and JEV result invalid' });
                expect(t.observe).not.toHaveBeenCalled();
            }
        );
    });

    it('does not hide an unexpected threshold failure as a JEV outage', async () => {
        const t = setup({ jev: async () => ATTACK });
        vi.spyOn(t.adaptive, 'classify').mockImplementation(() => {
            throw new TypeError('bug');
        });

        await expect(t.orchestrator.orchestrate(request(), verdict('SUSPICIOUS'))).rejects.toThrow(TypeError);
    });
});

describe('JEV results feeding adaptive control', () => {
    function wired(jev: () => Promise<DynamicVerdict>) {
        const adaptive = new AdaptiveControl();
        const orchestrator = new DecisionOrchestrator(
            { jev: { createVerdict: jev }, adaptive, sampler: new Sampler(), configFor: () => RUNTIME },
            CONFIG
        );
        const n = (tenantId: string) => adaptive.samplingProbability(tenantId, LOGIN, RUNTIME.sampling);
        return { orchestrator, n };
    }

    async function send(t: ReturnType<typeof wired>, times: number, tenantId: string, kind: StaticVerdict['verdict']) {
        const decisions = [];
        for (let i = 0; i < times; i++) decisions.push(await t.orchestrator.orchestrate(request(tenantId), verdict(kind)));
        return decisions;
    }

    it('raises N for the attacked tenant only', async () => {
        const t = wired(async () => ATTACK);

        await send(t, 10, TENANT, 'SUSPICIOUS');

        expect(t.n(TENANT)).toBeGreaterThan(0.4);
        expect(t.n(OTHER_TENANT)).toBeCloseTo(0.1, 5);
    });

    it('tightens the threshold under attack so a borderline result is blocked', async () => {
        let next = ATTACK;
        const t = wired(async () => next);
        await send(t, 30, TENANT, 'SUSPICIOUS');

        next = BORDERLINE;
        const [attacked] = await send(t, 1, TENANT, 'SUSPICIOUS');
        const [other] = await send(t, 1, OTHER_TENANT, 'SUSPICIOUS');

        expect(attacked.action).toBe('BLOCK');
        expect(attacked.jev!.threshold).toBeLessThan(0.6);
        expect(other.action).toBe('ALLOW');
    });

    it('is not moved by static policy violations or JEV failures', async () => {
        const violations = wired(async () => ATTACK);
        await send(violations, 50, TENANT, 'POLICY_VIOLATION');
        expect(violations.n(TENANT)).toBeCloseTo(0.1, 5);

        const failures = wired(jevDown);
        await send(failures, 50, TENANT, 'SUSPICIOUS');
        expect(failures.n(TENANT)).toBeCloseTo(0.1, 5);
    });
});
