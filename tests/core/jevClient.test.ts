import { describe, expect, it, vi } from 'vitest';
import { decode } from '@toon-format/toon';
import { JevClient, type JevModel } from '../../source/core/jev/client';
import type { StaticVerdict } from '../../source/core/static-analysis/aggregator';
import type { NormalizedRequest } from '../../source/shared/contracts';

const request: NormalizedRequest = {
    requestId: 'request-1',
    tenantId: 'tenant-a',
    endpoint: 'POST /userLogin',
    clientIp: '203.0.113.7',
    query: {},
    headers: { authorization: 'Bearer secret' },
    body: { login: 'Union Select', password: 'anything' },
    requestHash: 'hash',
    fields: [
        { name: 'login', value: 'Union Select', type: 'string', location: 'body' },
        { name: 'password', value: 'anything', type: 'string', location: 'body' },
    ],
    files: [],
    timestamp: 0,
};

const suspicious: StaticVerdict = {
    verdict: 'SUSPICIOUS',
    results: [{ tool: 'sql_injection', target: 'login', status: 'SUCCESS', verdict: 'SUSPICIOUS', evidence: ['union_select'] }],
    evidence: [['union_select']],
};

function fakeModel(noul: number, severity = 1) {
    const systemOne = vi.fn(async () => ({
        model: 'jev-test',
        answers: { attack: { type: 'noul', noul }, severity: { type: 'score', score: severity } },
        usage: { input_tokens: 0, output_tokens: 0 },
    }));
    return { model: { systemOne } as unknown as JevModel, systemOne };
}

const sentState = (systemOne: ReturnType<typeof fakeModel>['systemOne']) =>
    decode((systemOne.mock.calls[0] as unknown as [{ state: string }])[0].state) as Record<string, unknown>;

describe('JevClient', () => {
    it('sends only the endpoint, fields and field-attributed pattern matches', async () => {
        const { model, systemOne } = fakeModel(0.1);

        await new JevClient(model).createVerdict(request, suspicious);

        const state = sentState(systemOne);
        expect(state).toMatchObject({
            endpoint: 'POST /userLogin',
            fields: [
                { name: 'login', location: 'body', value: 'Union Select' },
                { name: 'password', location: 'body', value: 'anything' },
            ],
            patternMatches: [{ field: 'login', check: 'sql_injection', rules: ['union_select'] }],
        });
        const sent = JSON.stringify(state);
        for (const leaked of ['request-1', 'tenant-a', '203.0.113.7', 'Bearer secret', 'SUSPICIOUS']) {
            expect(sent).not.toContain(leaked);
        }
    });

    it('sends no pattern matches when static analysis found none', async () => {
        const { model, systemOne } = fakeModel(0.1);

        await new JevClient(model).createVerdict(request, { verdict: 'SAFE', results: [], evidence: undefined });

        expect(sentState(systemOne)).not.toHaveProperty('patternMatches');
    });

    it('uses P(attack) as the attack probability and its decisiveness as confidence', async () => {
        const { model } = fakeModel(0.9, 2.4);

        const verdict = await new JevClient(model).createVerdict(request, suspicious);

        expect(verdict.score).toBe(2.4);
        expect(verdict.attackProbability).toBe(0.9);
        expect(verdict.confidence).toBeCloseTo(0.8);
    });

    it.each([NaN, -0.1, 1.2, undefined as unknown as number])('rejects an attack probability of %s', async noul => {
        const { model } = fakeModel(noul);

        await expect(new JevClient(model).createVerdict(request, suspicious)).rejects.toThrow(RangeError);
    });
});
