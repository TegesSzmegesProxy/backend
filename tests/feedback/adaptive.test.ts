import { describe, expect, it } from 'vitest';
import { AdaptiveControl } from '../../source/feedback';
import { asymmetricEwma } from '../../source/feedback/metrics';
import { Sampler } from '../../source/core/sampling';
import type { SamplingConfig, ThresholdConfig } from '../../source/shared/contracts';

const TENANT = '3f2b8c1e-4a5d-4e6f-8a7b-9c0d1e2f3a4b';
const OTHER_TENANT = '7a1b2c3d-4e5f-4a6b-9c8d-0e1f2a3b4c5d';
const LOGIN = 'POST /login';

const sampling: SamplingConfig = { probabilityN: 0.2, minN: 0.05, maxN: 1 };
const thresholds: ThresholdConfig = {
    attackProbabilityThreshold: 0.8,
    attackProbabilityFloor: 0.5,
    locked: false,
};

function repeat(control: AdaptiveControl, tenantId: string, observation: 'ATTACK' | 'BENIGN' | 'UNSAMPLED', times: number) {
    for (let i = 0; i < times; i++) control.observe(tenantId, LOGIN, observation);
}

describe('asymmetricEwma', () => {
    it('rises faster than it falls', () => {
        const alpha = { up: 0.3, down: 0.02 };
        expect(asymmetricEwma(0, 1, alpha)).toBeCloseTo(0.3);
        expect(asymmetricEwma(1, 0, alpha)).toBeCloseTo(0.98);
    });
});

describe('adaptive sampling', () => {
    it('starts at the user-configured N', () => {
        const control = new AdaptiveControl();
        expect(control.samplingProbability(TENANT, LOGIN, sampling)).toBeCloseTo(0.2, 5);
    });

    it('rises under attack, stays within bounds, and decays toward minN when benign', () => {
        const control = new AdaptiveControl();
        control.samplingProbability(TENANT, LOGIN, sampling);

        repeat(control, TENANT, 'ATTACK', 50);
        const underAttack = control.samplingProbability(TENANT, LOGIN, sampling);
        expect(underAttack).toBeGreaterThan(0.9);
        expect(underAttack).toBeLessThanOrEqual(sampling.maxN);

        repeat(control, TENANT, 'BENIGN', 1000);
        const calm = control.samplingProbability(TENANT, LOGIN, sampling);
        expect(calm).toBeGreaterThanOrEqual(sampling.minN);
        expect(calm).toBeLessThan(0.1);
    });

    it('ignores unsampled requests', () => {
        const control = new AdaptiveControl();
        const before = control.samplingProbability(TENANT, LOGIN, sampling);
        repeat(control, TENANT, 'UNSAMPLED', 500);
        expect(control.samplingProbability(TENANT, LOGIN, sampling)).toBe(before);
    });

    it('does not leak attack rates across tenants', () => {
        const control = new AdaptiveControl();
        repeat(control, TENANT, 'ATTACK', 50);
        expect(control.samplingProbability(OTHER_TENANT, LOGIN, sampling)).toBeCloseTo(0.2, 5);
        expect(control.effectiveThresholds(OTHER_TENANT, LOGIN, thresholds).attackProbabilityThreshold).toBe(0.8);
    });
});

describe('tighten-only thresholds', () => {
    const borderline = { attackProbability: 0.7 };

    it('blocks a borderline result only after attacks tighten the threshold', () => {
        const control = new AdaptiveControl();
        expect(control.classify(borderline, control.effectiveThresholds(TENANT, LOGIN, thresholds))).toBe('BENIGN');

        repeat(control, TENANT, 'ATTACK', 30);
        const tightened = control.effectiveThresholds(TENANT, LOGIN, thresholds);
        expect(tightened.attackProbabilityThreshold).toBeLessThan(0.7);
        expect(tightened.attackProbabilityThreshold).toBeGreaterThanOrEqual(thresholds.attackProbabilityFloor);
        expect(control.classify(borderline, tightened)).toBe('ATTACK');
    });

    it('never loosens beyond the user value and lets unsampled traffic relax it back', () => {
        const control = new AdaptiveControl();
        repeat(control, TENANT, 'ATTACK', 30);
        repeat(control, TENANT, 'UNSAMPLED', 2000);
        const relaxed = control.effectiveThresholds(TENANT, LOGIN, thresholds).attackProbabilityThreshold;
        expect(relaxed).toBeLessThanOrEqual(0.8);
        expect(relaxed).toBeGreaterThan(0.79);
    });

    it('does not adapt locked thresholds', () => {
        const control = new AdaptiveControl();
        repeat(control, TENANT, 'ATTACK', 50);
        const locked = control.effectiveThresholds(TENANT, LOGIN, { ...thresholds, locked: true });
        expect(locked.attackProbabilityThreshold).toBe(0.8);
        expect(control.classify(borderline, locked)).toBe('BENIGN');
    });
});

describe('Sampler', () => {
    it('always samples suspicious requests and refuses blocked ones', () => {
        const sampler = new Sampler(() => 0.99);
        expect(sampler.shouldSample('SUSPICIOUS', 0.05)).toBe(true);
        expect(sampler.shouldSample('SAFE', 0.05)).toBe(false);
        expect(() => sampler.shouldSample('POLICY_VIOLATION', 1)).toThrow();
        expect(() => sampler.shouldSample('ERROR', 1)).toThrow();
    });
});
