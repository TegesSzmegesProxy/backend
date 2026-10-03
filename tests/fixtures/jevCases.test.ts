import { describe, expect, it } from 'vitest';
import { ALL_TOOL_IDS, loadFixture, runStatic, toolsFired } from './jevCases';

const fixture = loadFixture();

describe('JEV evaluation fixture', () => {
    it('holds 100 uniquely named cases, roughly half attacks', () => {
        const names = fixture.cases.map((c) => c.name);
        const attacks = fixture.cases.filter((c) => c.label === 'attack').length;

        expect(names).toHaveLength(100);
        expect(new Set(names).size).toBe(100);
        expect(attacks).toBeGreaterThanOrEqual(40);
        expect(attacks).toBeLessThanOrEqual(60);
    });

    it('explains every case and uses only declared endpoints', () => {
        for (const c of fixture.cases) {
            expect(c.why.length, c.name).toBeGreaterThan(5);
            expect(c.category, c.name).toMatch(/^(attack|benign)\//);
            expect(c.category.startsWith(c.label), c.name).toBe(true);
            expect(fixture.endpoints[c.endpoint], c.name).toBeDefined();
        }
    });

    it('runs through static analysis with no tool errors', () => {
        const broken = fixture.cases
            .map((c, index) => ({ name: c.name, verdict: runStatic(c, index, fixture).verdict.verdict }))
            .filter(({ verdict }) => verdict === 'ERROR');

        expect(broken).toEqual([]);
    });

    it('fires every static tool at least once', () => {
        const fired = new Set<string>();
        fixture.cases.forEach((c, index) => toolsFired(c, index, fixture).forEach((id) => fired.add(id)));

        // string_length is a policy limit no endpoint in the fixture opts into.
        const expected = ALL_TOOL_IDS.filter((id) => id !== 'string_length');
        expect(expected.filter((id) => !fired.has(id))).toEqual([]);
    });

    it('keeps the final static outcome the case is built to show', () => {
        const verdictOf = (name: string) => {
            const index = fixture.cases.findIndex((c) => c.name === name);
            return runStatic(fixture.cases[index], index, fixture).verdict.verdict;
        };

        expect(verdictOf('plain registration')).toBe('SAFE');
        expect(verdictOf('keyword login union select')).toBe('SUSPICIOUS');
        expect(verdictOf('oversized request body')).toBe('POLICY_VIOLATION');
        expect(verdictOf('credential stuffing burst')).toBe('POLICY_VIOLATION');
        expect(verdictOf('legit quick retry')).toBe('SUSPICIOUS');
        expect(verdictOf('internal user plain login')).toBe('SUSPICIOUS');
    });
});
