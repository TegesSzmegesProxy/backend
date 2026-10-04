import { describe, expect, it, vi } from 'vitest';
import { decode } from '@toon-format/toon';
import { JevClient, type JevModel, type VerdictStore } from '../../source/core/jev/client';
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

const noCache: VerdictStore = { get: async () => null, set: async () => {} };

const sentState = (systemOne: ReturnType<typeof fakeModel>['systemOne']) =>
    decode((systemOne.mock.calls[0] as unknown as [{ state: string }])[0].state) as Record<string, unknown>;

describe('JevClient', () => {
    it('sends only the endpoint, fields and field-attributed pattern matches', async () => {
        const { model, systemOne } = fakeModel(0.1);

        await new JevClient(model, noCache).createVerdict(request, suspicious);

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

    it('sends the policy context as labelled data, only for fields the request carries', async () => {
        const { model, systemOne } = fakeModel(0.1);

        await new JevClient(model, noCache).createVerdict(request, suspicious, {
            global: 'Account API.',
            endpoint: 'Signs a user in.',
            fields: [
                { target: 'body.login', context: 'An e-mail address or handle.' },
                { target: 'body.otp', context: 'Six digits.' },
            ],
        });

        const state = sentState(systemOne);
        expect(state['policyContext']).toEqual({
            global: 'Account API.',
            endpoint: 'Signs a user in.',
            fields: [{ field: 'body.login', description: 'An e-mail address or handle.' }],
        });
        expect(String(state['policyContextNote'])).toContain('not an instruction');
    });

    it('sends no policy context when the policy has none', async () => {
        const { model, systemOne } = fakeModel(0.1);

        await new JevClient(model, noCache).createVerdict(request, suspicious, {});

        expect(sentState(systemOne)).not.toHaveProperty('policyContext');
    });

    it('sends no pattern matches when static analysis found none', async () => {
        const { model, systemOne } = fakeModel(0.1);

        await new JevClient(model, noCache).createVerdict(request, { verdict: 'SAFE', results: [], evidence: undefined });

        expect(sentState(systemOne)).not.toHaveProperty('patternMatches');
    });

    it('uses P(attack) as the attack probability and its decisiveness as confidence', async () => {
        const { model } = fakeModel(0.9, 2.4);

        const verdict = await new JevClient(model, noCache).createVerdict(request, suspicious);

        expect(verdict.score).toBe(2.4);
        expect(verdict.attackProbability).toBe(0.9);
        expect(verdict.confidence).toBeCloseTo(0.8);
    });

    describe('verdict cache', () => {
        function memoryStore(): VerdictStore & { entries: Map<string, string> } {
            const entries = new Map<string, string>();
            return {
                entries,
                get: async (key) => entries.get(key) ?? null,
                set: async (key, value) => void entries.set(key, value),
            };
        }

        it('answers a repeated request from the cache', async () => {
            const { model, systemOne } = fakeModel(0.9);
            const client = new JevClient(model, memoryStore());

            await client.createVerdict(request, suspicious);
            const cached = await client.createVerdict(request, suspicious);

            expect(systemOne).toHaveBeenCalledTimes(1);
            expect(cached.attackProbability).toBe(0.9);
        });

        it('does not reuse a verdict for a request that differs only in its query', async () => {
            const { model, systemOne } = fakeModel(0.1);
            const client = new JevClient(model, memoryStore());
            const withQuery = (q: string): NormalizedRequest => ({
                ...request,
                body: undefined,
                fields: [{ name: 'q', value: q, type: 'string', location: 'query' }],
            });

            await client.createVerdict(withQuery('hello'), suspicious);
            await client.createVerdict(withQuery("' OR 1=1 --"), suspicious);

            expect(systemOne).toHaveBeenCalledTimes(2);
        });

        it('falls back to the model when the cache fails', async () => {
            const { model, systemOne } = fakeModel(0.9);
            const failing: VerdictStore = {
                get: async () => { throw new Error('redis down'); },
                set: async () => { throw new Error('redis down'); },
            };
            const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const error = vi.spyOn(console, 'error').mockImplementation(() => {});

            const verdict = await new JevClient(model, failing).createVerdict(request, suspicious);

            expect(verdict.attackProbability).toBe(0.9);
            expect(systemOne).toHaveBeenCalledTimes(1);
            warn.mockRestore();
            error.mockRestore();
        });

        it('ignores corrupt or out-of-range cache entries', async () => {
            const { model, systemOne } = fakeModel(0.9);
            const store = memoryStore();
            const client = new JevClient(model, store);
            await client.createVerdict(request, suspicious);
            const [key] = store.entries.keys();
            const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

            for (const entry of ['not json', 'null', JSON.stringify({ score: 0, attackProbability: 7, confidence: 1 })]) {
                store.entries.set(key, entry);
                await client.createVerdict(request, suspicious);
            }

            expect(systemOne).toHaveBeenCalledTimes(4);
            warn.mockRestore();
        });
    });

    it.each([NaN, -0.1, 1.2, undefined as unknown as number])('rejects an attack probability of %s', async noul => {
        const { model } = fakeModel(noul);

        await expect(new JevClient(model, noCache).createVerdict(request, suspicious)).rejects.toThrow(RangeError);
    });
});
