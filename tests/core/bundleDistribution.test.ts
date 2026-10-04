import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { BundleVerifier, canonicalJson, type SignedBundle } from '../../source/shared/contracts/bundle';
import { ActivePolicy } from '../../source/core/policy/ActivePolicy';
import { BundleFetcher, BundleVerificationError } from '../../source/core/policy/BundleFetcher';
import { fetchPolicies } from '../../source/core/policy/fetchPolicies';
import { PolicySnapshot } from '../../source/core/policy/PolicySnapshot';
import { PoliciesNotFetchedError, PolicyStore } from '../../source/core/policy/PolicyStore';
import { PolicyWatcher } from '../../source/core/policy/PolicyWatcher';
import { Tool, ToolContextType } from '../../source/core/static-analysis/shared';
import Fastify from 'fastify';
import { IngressServer } from '../../source/edge/ingress/server';
import { Normalizer } from '../../source/edge/normalizer';
import { Runner } from '../../source/core/static-analysis/runner';
import { Aggregator } from '../../source/core/static-analysis/aggregator';
import { DecisionOrchestrator } from '../../source/core/decisionOrchestrator';
import { AdaptiveControl } from '../../source/feedback';
import { Sampler } from '../../source/core/sampling';
import { ProxyReporter } from '../../source/shared/telemetry/ProxyReporter';
import type { TenantRedis } from '../../source/shared/storage';
import type { NormalizedRequest } from '../../source/shared/contracts';
import { MemoryToolState } from '../support/memoryToolState';

type BundleV2 = Extract<SignedBundle, { schemaVersion: 'tessera.bundle/v2' }>;

const TENANT = '3f2b8c1e4a5d4e6f8a7b9c0d';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
const keyId = createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex').slice(0, 32);

const RUNTIME = {
  upstreamUrl: 'http://localhost:9090', failureBehavior: 'block', unknownEndpointBehavior: 'block',
  routing: { pathPrefix: '/api' }, thresholds: { requestTimeoutMs: 1000, maxRequestBodyBytes: 1024 },
  samplingRate: 0.1,
  decision: {
    sampling: { minN: 0.01, maxN: 1 },
    jev: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false },
    onStaticAnalysisError: 'block', onSuspiciousJevUnavailable: 'block', onSampledJevUnavailable: 'allow',
  },
};

function signed(content: Record<string, unknown>): SignedBundle {
  const version = createHash('sha256').update(canonicalJson(content)).digest('hex');
  const payload = { ...content, version, issuedAt: '2026-10-04T00:00:00.000Z' };
  return { ...payload, signature: { algorithm: 'Ed25519', keyId, value: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64url') } } as SignedBundle;
}

function bundle(overrides: Record<string, unknown> = {}): SignedBundle {
  return signed({
    schemaVersion: 'tessera.bundle/v2',
    tenantId: TENANT,
    policyVersion: 'policy-1',
    runtimeConfig: RUNTIME,
    policy: { schemaVersion: 'tessera.policy/v1', toolRegistryVersion: 'tessera.tools/v1', endpoints: [
      { method: 'POST', path: '/users/:id', steps: [
        { toolId: 'string_length', contextType: 'field', target: 'body.username', config: { minLength: 3, maxLength: 8 } },
      ] },
    ] },
    ...overrides,
  });
}

const POLICY_V3 = {
  schemaVersion: 'tessera.policy/v3',
  toolRegistryVersion: 'tessera.tools/v3',
  global: {
    steps: [
      { toolId: 'sql_injection', contextType: 'field', target: 'body.*', config: {} },
      { toolId: 'null_byte', contextType: 'field', target: '*', config: {} },
      { toolId: 'string_length', contextType: 'field', target: 'body.username', config: { operator: '<=', length: 100 } },
    ],
    jevContext: 'A JSON API for managing user accounts.',
  },
  environment: {
    steps: [{ toolId: 'jndi_lookup', contextType: 'field', target: 'body.*', config: {} }],
    jevContext: 'The service runs a Java logging library with a known JNDI lookup issue.',
    environmentSnapshotId: '5f2b8c1e4a5d4e6f8a7b9c0d',
  },
  endpoints: [
    {
      method: 'POST', path: '/users/:id',
      steps: [{ toolId: 'string_length', contextType: 'field', target: 'body.username', config: { operator: '<=', length: 8 } }],
      jevContext: 'Updates a user profile.',
      fieldContexts: [
        { target: 'body.username', jevContext: 'A short handle of letters and digits.' },
        { target: 'body.items[].sku', jevContext: 'Catalogue code.' },
      ],
    },
  ],
};

function bundleV3(policy: Record<string, unknown> = {}, runtimeConfig: Record<string, unknown> = {}): SignedBundle {
  return signed({
    schemaVersion: 'tessera.bundle/v3',
    tenantId: TENANT,
    policyVersion: 'policy-3',
    runtimeConfig: { ...RUNTIME, ...runtimeConfig },
    policy: { ...POLICY_V3, ...policy },
  });
}

/** In-memory stand-in for the TenantRedis calls PolicyStore makes. */
class MemoryPolicyRedis {
  readonly values = new Map<string, string>();
  readonly listeners: ((message: string) => void)[] = [];
  down = false;

  private guard(): void { if (this.down) throw new Error('The client is closed'); }
  async get(name: string) { this.guard(); return this.values.get(name) ?? null; }
  async transaction(sets: [string, string][], deletes: string[] = []) {
    this.guard();
    for (const [name, value] of sets) this.values.set(name, value);
    for (const name of deletes) this.values.delete(name);
  }
  async publish(_channel: string, message: string) { for (const listener of this.listeners) listener(message); }
  async subscribe(_channel: string, listener: (message: string) => void) {
    this.listeners.push(listener);
    return async () => undefined;
  }
  asTenantRedis(): TenantRedis { return this as unknown as TenantRedis; }
}

const state = new MemoryToolState();
const verifier = () => new BundleVerifier(publicPem, TENANT);
const load = (raw: unknown) => new PolicySnapshot(verifier().verify(raw), state.stores);
const compile = (value: SignedBundle) => new PolicySnapshot(value, state.stores);
const field = (name: string, value: unknown, location = 'body') => ({ name, location, value, type: typeof value });
const request = (fields: ReturnType<typeof field>[]): NormalizedRequest => ({
  requestId: 'r1', tenantId: TENANT, endpoint: 'POST /users/:id', clientIp: '127.0.0.1', query: {}, headers: {}, body: {},
  requestHash: 'h', fields, files: [], timestamp: Date.now(),
});
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; vi.restoreAllMocks(); });

describe('bundle verification', () => {
  it('verifies hash, signature, tenant and every tool before execution', () => {
    const valid = bundle() as BundleV2;
    expect(verifier().verify(valid).version).toBe(valid.version);
    expect(() => verifier().verify({ ...valid, tenantId: 'aaaaaaaaaaaaaaaaaaaaaaaa' })).toThrow();
    expect(() => verifier().verify({ ...valid, version: '0'.repeat(64) })).toThrow();
    expect(() => verifier().verify(bundle({ tenantId: 'aaaaaaaaaaaaaaaaaaaaaaaa' }))).toThrow('tenant');
    const unknown = bundle({ policy: { ...valid.policy, endpoints: [
      { ...valid.policy.endpoints[0], steps: [{ ...valid.policy.endpoints[0].steps[0], toolId: 'unknown' }] },
    ] } });
    expect(() => verifier().verify(unknown)).toThrow();
    const invalidSampling = bundle({ runtimeConfig: {
      ...RUNTIME,
      samplingRate: 0,
      decision: { ...RUNTIME.decision, sampling: { minN: 0, maxN: 1 } },
    } });
    expect(() => verifier().verify(invalidSampling)).toThrow();
  });

  it('validates every step against its tool contract and keeps accepting v1 bundles', () => {
    const withSteps = (steps: unknown[], toolRegistryVersion = 'tessera.tools/v2') => bundle({ policy: {
      schemaVersion: 'tessera.policy/v1', toolRegistryVersion, endpoints: [{ method: 'POST', path: '/login', steps }],
    } });
    const valid = [
      { toolId: 'brute_force', contextType: 'full', config: { attempts: { suspicious: 2, block: 3 } } },
      { toolId: 'rate_limit', contextType: 'full', config: {} },
      { toolId: 'enum_validation', contextType: 'field', target: 'body.currency', config: { values: ['PLN', 'EUR'] } },
      { toolId: 'file_size', contextType: 'file', target: 'avatar', config: { maxBytes: 1024 } },
    ];
    const verified = verifier().verify(withSteps(valid)) as BundleV2;
    // the signed config is kept as sent; defaults are applied when the tool is built
    expect(verified.policy.endpoints[0].steps[1].config).toEqual({});
    const plan = new PolicySnapshot(verified, state.stores).match('POST', '/api/login')!.plan;
    expect(plan.map((step) => step.tool.tool)).toEqual(['brute_force', 'rate_limit', 'enum_validation', 'file_size']);

    const rejects = (step: Record<string, unknown>) => expect(() => verifier().verify(withSteps([step]))).toThrow();
    rejects({ toolId: 'sql_injection', contextType: 'full', config: {} }); // a field tool run as a whole-request tool
    rejects({ toolId: 'sql_injection', contextType: 'field', config: {} }); // no target
    rejects({ toolId: 'sql_injection', contextType: 'field', target: 'body.*', config: {} }); // wildcards are for scopes
    rejects({ toolId: 'rate_limit', contextType: 'full', target: 'body.x', config: {} });
    rejects({ toolId: 'rate_limit', contextType: 'full', config: { limit: -1 } });
    rejects({ toolId: 'rate_limit', contextType: 'full', config: { limit: 5, unknownSetting: true } });
    rejects({ toolId: 'honeypot_field', contextType: 'full', config: {} }); // required setting missing
    rejects({ toolId: 'cookie_tampering', contextType: 'full', config: { secret: 'short', signedCookies: ['session'] } });

    const v1Step = { toolId: 'string_length', contextType: 'field', target: 'body.name', config: { maxLength: 5 } };
    expect(verifier().verify(withSteps([v1Step], 'tessera.tools/v1')).policy.toolRegistryVersion).toBe('tessera.tools/v1');
    expect(() => verifier().verify(withSteps([valid[1]], 'tessera.tools/v1'))).toThrow();
    expect(() => verifier().verify(withSteps([valid[1]], 'tessera.tools/v4'))).toThrow();

    const v3Step = { toolId: 'php_object_injection', contextType: 'field', target: 'body.data', config: {} };
    expect(verifier().verify(withSteps([v3Step, valid[1]], 'tessera.tools/v3')).policy.toolRegistryVersion).toBe('tessera.tools/v3');
    expect(() => verifier().verify(withSteps([v3Step]))).toThrow(); // php_object_injection needs tessera.tools/v3
  });

  it('verifies scoped v3 bundles and limits wildcards and JEV context', () => {
    expect(verifier().verify(bundleV3()).schemaVersion).toBe('tessera.bundle/v3');
    // a scope-only policy (no endpoints) is valid
    expect(verifier().verify(bundleV3({ endpoints: [] })).policy.endpoints).toEqual([]);
    const rejects = (policy: Record<string, unknown>) => expect(() => verifier().verify(bundleV3(policy))).toThrow();
    rejects({ endpoints: [{ ...POLICY_V3.endpoints[0], steps: [{ toolId: 'sql_injection', contextType: 'field', target: 'body.*', config: {} }] }] });
    rejects({ global: { ...POLICY_V3.global, steps: [{ toolId: 'file_size', contextType: 'file', target: 'body.*', config: {} }] } });
    rejects({ global: { ...POLICY_V3.global, jevContext: 'x'.repeat(1_501) } });
    rejects({ toolRegistryVersion: 'tessera.tools/v2' });
    // the human-readable policy never reaches a proxy
    rejects({ endpoints: [{ ...POLICY_V3.endpoints[0], humanReadablePolicy: 'never shipped' }] });
  });
});

describe('policy snapshot', () => {
  it('matches policy paths and enforces configured string lengths on body targets', async () => {
    const snapshot = new PolicySnapshot(bundle(), state.stores);
    const route = snapshot.match('POST', '/api/users/42');
    expect(route?.key).toBe('POST /users/:id');
    expect(route?.upstreamPath).toBe('/users/42');
    expect(snapshot.match('POST', '/other/users/42')).toBeUndefined();
    const step = route!.plan[0];
    if (!('target' in step)) throw new Error('expected field tool');
    expect(step.target).toBe('body.username');
    const tool = step.tool as Tool<ToolContextType.Field>;
    expect((await tool.run({ name: 'username', location: 'body', value: 'ab', type: 'string' })).verdict).toBe('POLICY_VIOLATION');
    expect((await tool.run({ name: 'username', location: 'body', value: 'alice', type: 'string' })).verdict).toBe('SAFE');
    expect((await tool.run({ name: 'username', location: 'body', value: 'longusername', type: 'string' })).verdict).toBe('POLICY_VIOLATION');
    const base = bundle() as BundleV2;
    const withExact = bundle({ policy: { ...base.policy, endpoints: [
      ...base.policy.endpoints,
      { ...base.policy.endpoints[0], path: '/users/new' },
    ] } });
    const exactSnapshot = load(withExact);
    expect(exactSnapshot.match('POST', '/api/users/new')?.key).toBe('POST /users/new');
    expect(exactSnapshot.match('POST', '/api/users/42/')?.key).toBeUndefined();
  });

  it('merges global, environment and endpoint steps, the most specific scope winning', () => {
    const snapshot = load(bundleV3());
    const route = snapshot.match('POST', '/api/users/42')!;
    const steps = route.plan.map((step) => `${step.tool.tool}:${'target' in step ? step.target : ''}`);
    // the endpoint's string_length on body.username replaces the global one
    expect(steps).toEqual(['sql_injection:body.*', 'null_byte:*', 'jndi_lookup:body.*', 'string_length:body.username']);
    expect(route.context).toEqual({
      global: POLICY_V3.global.jevContext,
      environment: POLICY_V3.environment.jevContext,
      endpoint: 'Updates a user profile.',
      fields: [
        { target: 'body.username', context: 'A short handle of letters and digits.' },
        { target: 'body.items[].sku', context: 'Catalogue code.' },
      ],
    });
    const unknown = snapshot.matchUnknown('/api/other');
    expect(unknown.key).toBeNull();
    expect(unknown.upstreamPath).toBe('/other');
    expect(unknown.plan.map((step) => step.tool.tool)).toEqual(['sql_injection', 'null_byte', 'string_length', 'jndi_lookup']);
    expect(unknown.context).toEqual({ global: POLICY_V3.global.jevContext, environment: POLICY_V3.environment.jevContext });
    expect(snapshot.summary).toEqual({ global: 3, environment: 1, endpoints: 1, endpointSteps: 1 });
    // global steps are shared by every route, so their state is too
    expect(snapshot.match('POST', '/api/users/1')!.plan[0]).toBe(unknown.plan[0]);
  });

  it('runs wildcard and array-item targets on every matching field', async () => {
    const snapshot = load(bundleV3({ endpoints: [{ ...POLICY_V3.endpoints[0], steps: [
      { toolId: 'string_length', contextType: 'field', target: 'body.items[].sku', config: { operator: '<=', length: 3 } },
    ] }] }));
    const route = snapshot.match('POST', '/api/users/1')!;
    const results = await new Runner().run(request([
      field('username', 'alice'), field('items.0.sku', 'abc'), field('items.1.sku', 'toolong'), field('q', 'x', 'query'),
    ]), route.plan);
    const targets = (tool: string) => results.filter((result) => result.tool === tool).map((result) => result.target);
    expect(targets('sql_injection')).toEqual(['body.username', 'body.items.0.sku', 'body.items.1.sku']);
    expect(targets('null_byte')).toEqual(['body.username', 'body.items.0.sku', 'body.items.1.sku', 'query.q']);
    const lengths = results.filter((result) => result.tool === 'string_length' && result.target?.startsWith('body.items'));
    expect(lengths.map((result) => [result.target, result.verdict])).toEqual([
      ['body.items.0.sku', 'SAFE'], ['body.items.1.sku', 'POLICY_VIOLATION'],
    ]);
  });
});

describe('policy fetch and Redis store', () => {
  const respond = (body: SignedBundle) => vi.fn(async (_url: unknown, init?: RequestInit) => {
    const ifNoneMatch = new Headers(init?.headers).get('if-none-match');
    if (ifNoneMatch === `"${body.version}"`) return new Response(null, { status: 304 });
    return new Response(JSON.stringify(body), { status: 200, headers: { etag: `"${body.version}"` } });
  });
  const fetcher = () => new BundleFetcher({ tenantId: TENANT, apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret' }, verifier());

  it('stores a verified bundle only after every tool builds, and reports when it is unchanged', async () => {
    const redis = new MemoryPolicyRedis();
    const store = new PolicyStore(redis.asTenantRedis());
    expect(await store.loadActive()).toBeNull();
    expect(new PoliciesNotFetchedError(TENANT).message).toContain('tessera fetch');

    const first = bundleV3();
    globalThis.fetch = respond(first);
    const stored = await fetchPolicies({ fetcher: fetcher(), store, compile });
    expect(stored).toMatchObject({ status: 'updated', version: first.version, previousVersion: null });
    expect(await store.activeVersion()).toBe(first.version);
    expect(load(await store.loadActive()).version).toBe(first.version);
    const headers = new Headers((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0]![1]?.headers);
    expect(headers.get('tessera-bundle-schemas')).toBe('tessera.bundle/v3, tessera.bundle/v2');

    expect((await fetchPolicies({ fetcher: fetcher(), store, compile })).status).toBe('unchanged');

    const second = bundleV3({}, { samplingRate: 0.2 });
    globalThis.fetch = respond(second);
    const failing = fetchPolicies({ fetcher: fetcher(), store, compile: () => { throw new Error('tool cannot run here'); } });
    await expect(failing).rejects.toThrow('tool cannot run here');
    expect(await store.activeVersion()).toBe(first.version);

    const updated = await fetchPolicies({ fetcher: fetcher(), store, compile });
    expect(updated).toMatchObject({ status: 'updated', version: second.version, previousVersion: first.version });
    expect(redis.values.get('previous')).toBe(first.version);

    globalThis.fetch = respond({ ...bundleV3({}, { samplingRate: 0.3 }), version: '0'.repeat(64) } as SignedBundle);
    await expect(fetchPolicies({ fetcher: fetcher(), store, compile })).rejects.toBeInstanceOf(BundleVerificationError);
    expect(await store.activeVersion()).toBe(second.version);
  });

  it('hot-swaps a newly fetched policy and never applies one that fails verification or changes the upstream', async () => {
    const redis = new MemoryPolicyRedis();
    const store = new PolicyStore(redis.asTenantRedis());
    await store.save(bundleV3());
    const active = new ActivePolicy(load(await store.loadActive()));
    const watcher = new PolicyWatcher(store, active, load, 60_000);
    await watcher.start();
    try {
      const next = bundleV3({}, { samplingRate: 0.5 });
      await store.save(next);
      await watcher.check();
      expect(active.snapshot.version).toBe(next.version);

      const tampered = { ...bundleV3({}, { samplingRate: 0.6 }), policyVersion: 'edited in Redis' };
      await redis.transaction([[`bundle:${tampered.version}`, JSON.stringify(tampered)], ['active', tampered.version]]);
      await watcher.check();
      expect(active.snapshot.version).toBe(next.version);
      expect(active.status.reloadFailures).toBe(1);

      await store.save(bundleV3({}, { upstreamUrl: 'http://elsewhere:9090' }));
      await watcher.check();
      expect(active.snapshot.version).toBe(next.version);
      expect(active.status.restartRequired).toBe(true);

      redis.down = true;
      await watcher.check();
      expect(active.snapshot.version).toBe(next.version);
    } finally { await watcher.stop(); }
  });

  it('reports a newer dashboard bundle without applying it', async () => {
    const running = bundleV3();
    const active = new ActivePolicy(load(running), fetcher());
    globalThis.fetch = respond(running);
    await active.checkForUpdate();
    expect(active.status).toMatchObject({ updateAvailable: false, dashboardReachable: true, source: 'last_known_good' });
    globalThis.fetch = respond(bundleV3({}, { samplingRate: 0.9 }));
    await active.checkForUpdate();
    expect(active.status.updateAvailable).toBe(true);
    expect(active.snapshot.version).toBe(running.version);
    globalThis.fetch = vi.fn(async () => { throw new Error('offline'); });
    await active.checkForUpdate();
    expect(active.status).toMatchObject({ dashboardReachable: false, pullFailures: 1 });
  });
});

describe('ingress', () => {
  it('forwards allowed traffic, blocks violations, and runs global policies on unknown endpoints', async () => {
    const upstream = Fastify();
    upstream.post('/users/:id', async (request) => ({ id: (request.params as { id: string }).id, body: request.body }));
    upstream.post('/other', async () => ({ forwarded: true }));
    const upstreamUrl = await upstream.listen({ port: 0, host: '127.0.0.1' });
    const runtime = { upstreamUrl, samplingRate: 0, decision: { ...RUNTIME.decision, sampling: { minN: 0, maxN: 0 } } };
    const contexts: unknown[] = [];
    const orchestrator = new DecisionOrchestrator({
      jev: { createVerdict: async (_request, _verdict, context) => { contexts.push(context); throw new Error('JEV unavailable'); } },
      adaptive: new AdaptiveControl(),
      sampler: new Sampler(),
      configFor: () => ({ sampling: { probabilityN: 0, minN: 0, maxN: 0 }, threshold: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false } }),
    }, { staticAnalysisError: 'BLOCK', suspiciousWhenJevUnavailable: 'BLOCK', sampledWhenJevUnavailable: 'BLOCK' });
    const policy = new ActivePolicy(load(bundle({ runtimeConfig: { ...RUNTIME, ...runtime } })));
    const reporter = new ProxyReporter({ tenantId: TENANT, apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret', proxyVersion: 'test' }, policy);
    const ingress = new IngressServer({ normalizer: new Normalizer(), runner: new Runner(), aggregator: new Aggregator(), orchestrator, policy, reporter }, { tenantId: TENANT, port: 0, host: '127.0.0.1' });
    try {
      const address = await ingress.start();
      const post = (path: string, body: Record<string, unknown>) => fetch(`${address}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const allowed = await post('/api/users/42', { username: 'alice' });
      expect(allowed.status).toBe(200);
      expect(await allowed.json()).toEqual({ id: '42', body: { username: 'alice' } });
      expect((await post('/api/users/42', { username: 'ab' })).status).toBe(403);
      expect((await post('/api/other', { username: 'alice' })).status).toBe(403);

      // a fetched v3 policy is swapped in between requests; unknown endpoints are allowed but still run global steps
      expect(policy.swap(load(bundleV3({}, { ...runtime, unknownEndpointBehavior: 'allow' })))).toBe(true);
      const unknown = await post('/api/other', { comment: 'hello' });
      expect(unknown.status).toBe(200);
      expect(await unknown.json()).toEqual({ forwarded: true });
      expect((await post('/api/other', { comment: "' OR 1=1 --" })).status).toBe(403);
      expect(contexts[contexts.length - 1]).toEqual({ global: POLICY_V3.global.jevContext, environment: POLICY_V3.environment.jevContext });
      expect((await post('/api/users/42', { username: 'toolongname' })).status).toBe(403);
      expect((await post('/api/users/42', { username: 'x'.repeat(2_000) })).status).toBe(413);
    } finally { await ingress.stop(); await upstream.close(); }
  });
});
