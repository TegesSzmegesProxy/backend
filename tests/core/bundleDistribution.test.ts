import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BundleVerifier, canonicalJson, type SignedBundle } from '../../source/shared/contracts/bundle';
import { BundleManager } from '../../source/core/policy/BundleManager';
import { PolicySnapshot } from '../../source/core/policy/PolicySnapshot';
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
import { MemoryToolState } from '../support/memoryToolState';

const TENANT = '3f2b8c1e4a5d4e6f8a7b9c0d';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
const keyId = createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex').slice(0, 32);

function bundle(overrides: Record<string, unknown> = {}): SignedBundle {
  const content = {
    schemaVersion: 'tessera.bundle/v2',
    tenantId: TENANT,
    policyVersion: 'policy-1',
    runtimeConfig: {
      upstreamUrl: 'http://localhost:9090', failureBehavior: 'block', unknownEndpointBehavior: 'block',
      routing: { pathPrefix: '/api' }, thresholds: { requestTimeoutMs: 1000, maxRequestBodyBytes: 1024 },
      samplingRate: 0.1,
      decision: {
        sampling: { minN: 0.01, maxN: 1 },
        jev: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false },
        onStaticAnalysisError: 'block', onSuspiciousJevUnavailable: 'block', onSampledJevUnavailable: 'allow',
      },
    },
    policy: { schemaVersion: 'tessera.policy/v1', toolRegistryVersion: 'tessera.tools/v1', endpoints: [
      { method: 'POST', path: '/users/:id', steps: [
        { toolId: 'string_length', contextType: 'field', target: 'body.username', config: { minLength: 3, maxLength: 8 } },
      ] },
    ] },
    ...overrides,
  };
  const version = createHash('sha256').update(canonicalJson(content)).digest('hex');
  const payload = { ...content, version, issuedAt: '2026-10-04T00:00:00.000Z' };
  return { ...payload, signature: { algorithm: 'Ed25519', keyId, value: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64url') } } as SignedBundle;
}

const state = new MemoryToolState();
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; vi.restoreAllMocks(); });

describe('bundle distribution', () => {
  it('verifies hash, signature, tenant and every tool before execution', () => {
    const verifier = new BundleVerifier(publicPem, TENANT);
    const valid = bundle();
    expect(verifier.verify(valid).version).toBe(valid.version);
    expect(() => verifier.verify({ ...valid, tenantId: 'aaaaaaaaaaaaaaaaaaaaaaaa' })).toThrow();
    expect(() => verifier.verify({ ...valid, version: '0'.repeat(64) })).toThrow();
    expect(() => verifier.verify(bundle({ tenantId: 'aaaaaaaaaaaaaaaaaaaaaaaa' }))).toThrow('tenant');
    const unknown = bundle({ policy: { ...valid.policy, endpoints: [
      { ...valid.policy.endpoints[0], steps: [{ ...valid.policy.endpoints[0].steps[0], toolId: 'unknown' }] },
    ] } });
    expect(() => verifier.verify(unknown)).toThrow();
    const invalidSampling = bundle({ runtimeConfig: {
      ...valid.runtimeConfig,
      samplingRate: 0,
      decision: { ...valid.runtimeConfig.decision, sampling: { minN: 0, maxN: 1 } },
    } });
    expect(() => verifier.verify(invalidSampling)).toThrow();
  });

  it('validates every step against its tool contract and keeps accepting v1 bundles', () => {
    const verifier = new BundleVerifier(publicPem, TENANT);
    const withSteps = (steps: unknown[], toolRegistryVersion = 'tessera.tools/v2') => bundle({ policy: {
      schemaVersion: 'tessera.policy/v1', toolRegistryVersion, endpoints: [{ method: 'POST', path: '/login', steps }],
    } });
    const valid = [
      { toolId: 'brute_force', contextType: 'full', config: { attempts: { suspicious: 2, block: 3 } } },
      { toolId: 'rate_limit', contextType: 'full', config: {} },
      { toolId: 'enum_validation', contextType: 'field', target: 'body.currency', config: { values: ['PLN', 'EUR'] } },
      { toolId: 'file_size', contextType: 'file', target: 'avatar', config: { maxBytes: 1024 } },
    ];
    const verified = verifier.verify(withSteps(valid));
    // the signed config is kept as sent; defaults are applied when the tool is built
    expect(verified.policy.endpoints[0].steps[1].config).toEqual({});
    const plan = new PolicySnapshot(verified, state.stores).match('POST', '/api/login')!.plan;
    expect(plan.map((step) => step.tool.tool)).toEqual(['brute_force', 'rate_limit', 'enum_validation', 'file_size']);

    const rejects = (step: Record<string, unknown>) => expect(() => verifier.verify(withSteps([step]))).toThrow();
    rejects({ toolId: 'sql_injection', contextType: 'full', config: {} }); // a field tool run as a whole-request tool
    rejects({ toolId: 'sql_injection', contextType: 'field', config: {} }); // no target
    rejects({ toolId: 'rate_limit', contextType: 'full', target: 'body.x', config: {} });
    rejects({ toolId: 'rate_limit', contextType: 'full', config: { limit: -1 } });
    rejects({ toolId: 'rate_limit', contextType: 'full', config: { limit: 5, unknownSetting: true } });
    rejects({ toolId: 'honeypot_field', contextType: 'full', config: {} }); // required setting missing
    rejects({ toolId: 'cookie_tampering', contextType: 'full', config: { secret: 'short', signedCookies: ['session'] } });

    const v1Step = { toolId: 'string_length', contextType: 'field', target: 'body.name', config: { maxLength: 5 } };
    expect(verifier.verify(withSteps([v1Step], 'tessera.tools/v1')).policy.toolRegistryVersion).toBe('tessera.tools/v1');
    expect(() => verifier.verify(withSteps([valid[1]], 'tessera.tools/v1'))).toThrow();
    expect(() => verifier.verify(withSteps([valid[1]], 'tessera.tools/v3'))).toThrow();
  });

  it('uses the last verified disk copy during an outage and never switches a running snapshot', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'tessera-bundle-'));
    const cacheFile = join(dir, 'bundle.json');
    const options = { tenantId: TENANT, apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret', cacheFile };
    const verifier = new BundleVerifier(publicPem, TENANT);
    const first = bundle();
    try {
      globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(first), { status: 200, headers: { etag: `"${first.version}"` } }));
      const active = new BundleManager(options, verifier);
      expect((await active.start()).version).toBe(first.version);
      expect(JSON.parse(await readFile(cacheFile, 'utf8')).version).toBe(first.version);
      const next = bundle({ policyVersion: 'policy-2' });
      globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(next), { status: 200, headers: { etag: `"${next.version}"` } }));
      await active.checkForUpdate();
      expect(active.status.restartRequired).toBe(true);
      expect(active.snapshot.version).toBe(first.version);
      expect(JSON.parse(await readFile(cacheFile, 'utf8')).version).toBe(next.version);
      globalThis.fetch = vi.fn(async () => { throw new Error('offline'); });
      const restarted = new BundleManager(options, verifier);
      expect((await restarted.start()).version).toBe(next.version);
      expect(restarted.status.source).toBe('last_known_good');
      globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ ...next, version: '0'.repeat(64) }), { status: 200 }));
      const afterTamper = new BundleManager(options, verifier);
      expect((await afterTamper.start()).version).toBe(next.version);
      expect(afterTamper.status.verificationFailures).toBe(1);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('does not start without a verified remote bundle or local copy', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'tessera-first-start-'));
    try {
      globalThis.fetch = vi.fn(async () => { throw new Error('offline'); });
      const manager = new BundleManager({ tenantId: TENANT, apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret', cacheFile: join(dir, 'missing.json') }, new BundleVerifier(publicPem, TENANT));
      await expect(manager.start()).rejects.toThrow('No valid bundle');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

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
    const base = bundle();
    const withExact = bundle({ policy: { ...base.policy, endpoints: [
      ...base.policy.endpoints,
      { ...base.policy.endpoints[0], path: '/users/new' },
    ] } });
    const exactSnapshot = new PolicySnapshot(new BundleVerifier(publicPem, TENANT).verify(withExact), state.stores);
    expect(exactSnapshot.match('POST', '/api/users/new')?.key).toBe('POST /users/new');
    expect(exactSnapshot.match('POST', '/api/users/42/')?.key).toBeUndefined();
  });

  it('forwards allowed traffic and blocks configured violations and unknown endpoints', async () => {
    const upstream = Fastify();
    upstream.post('/users/:id', async (request) => ({ id: (request.params as { id: string }).id, body: request.body }));
    upstream.post('/other', async () => ({ forwarded: true }));
    const upstreamUrl = await upstream.listen({ port: 0, host: '127.0.0.1' });
    const base = bundle();
    const signed = bundle({ runtimeConfig: {
      ...base.runtimeConfig,
      upstreamUrl,
      samplingRate: 0,
      decision: { ...base.runtimeConfig.decision, sampling: { minN: 0, maxN: 0 } },
    } });
    const snapshot = new PolicySnapshot(new BundleVerifier(publicPem, TENANT).verify(signed), state.stores);
    const manager = new BundleManager({ tenantId: TENANT, apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret', cacheFile: '/unused' }, new BundleVerifier(publicPem, TENANT));
    const reporter = new ProxyReporter({ tenantId: TENANT, apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret', proxyVersion: 'test' }, manager);
    const orchestrator = new DecisionOrchestrator({
      jev: { createVerdict: async () => { throw new Error('unexpected JEV call'); } },
      adaptive: new AdaptiveControl(),
      sampler: new Sampler(),
      configFor: () => ({ sampling: { probabilityN: 0, minN: 0, maxN: 0 }, threshold: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false } }),
    }, { staticAnalysisError: 'BLOCK', suspiciousWhenJevUnavailable: 'BLOCK', sampledWhenJevUnavailable: 'BLOCK' });
    const ingress = new IngressServer({ normalizer: new Normalizer(), runner: new Runner(), aggregator: new Aggregator(), orchestrator, snapshot, reporter }, { tenantId: TENANT, port: 0, host: '127.0.0.1' });
    try {
      const address = await ingress.start();
      const post = (path: string, username: string) => fetch(`${address}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
      const allowed = await post('/api/users/42', 'alice');
      expect(allowed.status).toBe(200);
      expect(await allowed.json()).toEqual({ id: '42', body: { username: 'alice' } });
      expect((await post('/api/users/42', 'ab')).status).toBe(403);
      expect((await post('/api/other', 'alice')).status).toBe(403);
      const allowUnknown = bundle({ runtimeConfig: { ...signed.runtimeConfig, unknownEndpointBehavior: 'allow' } });
      const allowedSnapshot = new PolicySnapshot(new BundleVerifier(publicPem, TENANT).verify(allowUnknown), state.stores);
      const otherIngress = new IngressServer({ normalizer: new Normalizer(), runner: new Runner(), aggregator: new Aggregator(), orchestrator, snapshot: allowedSnapshot, reporter }, { tenantId: TENANT, port: 0, host: '127.0.0.1' });
      try {
        const otherAddress = await otherIngress.start();
        const unknown = await fetch(`${otherAddress}/api/other`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        expect(unknown.status).toBe(200);
        expect(await unknown.json()).toEqual({ forwarded: true });
      } finally { await otherIngress.stop(); }
    } finally { await ingress.stop(); await upstream.close(); }
  });
});
