import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TOOL_IDS, type ToolId, toolContract, toolRegistryDocument } from '../../source/shared/contracts/tools';
import { createTool } from '../../source/core/static-analysis';
import { Runner } from '../../source/core/static-analysis/runner';
import { ToolContextType, ToolState, type Tool } from '../../source/core/static-analysis/shared';
import type { NormalizedRequest } from '../../source/shared/contracts';
import { MemoryToolState } from '../support/memoryToolState';

const TENANT = '3f2b8c1e4a5d4e6f8a7b9c0d';
const OTHER_TENANT = 'aaaaaaaaaaaaaaaaaaaaaaaa';

const ORIGINS = { allowedOrigins: ['https://example.com'] };
const HOSTS = { allowedHosts: ['example.com'] };
const GEO_IP = [{ cidr: '81.2.69.0/24', country: 'GB', city: 'London', lat: 51.51, lon: -0.13 }];

/** The smallest valid configuration of every tool with required settings; all others run on defaults. */
const REQUIRED: Partial<Record<ToolId, Record<string, unknown>>> = {
  additional_properties: { properties: ['name'] },
  array_uniqueness: { properties: ['codes'] },
  enum_validation: { values: ['PLN'] },
  format_validation: { format: 'email' },
  integer_range: { min: 0 },
  json_schema: { schema: { type: 'object' } },
  openapi_conformance: { queryParameters: ['page'] },
  regex_pattern: { pattern: '[a-z]+' },
  required_fields: { fields: ['name'] },
  string_length: { maxLength: 10 },
  type_coercion: { expectedType: 'boolean' },
  honeypot_field: { fields: ['website'] },
  referer_anomaly: ORIGINS,
  cookie_tampering: { secret: 'a-secret-of-16-chars', signedCookies: ['session'] },
  csrf: ORIGINS,
  impossible_travel: { geoIp: GEO_IP },
  jwt_validation: { publicKey: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----' },
  oauth_flow_validation: { callbackRoutes: ['/oauth/callback'] },
  datacenter_asn: { asnTable: [{ cidr: '3.0.0.0/9', asn: 16509, org: 'Amazon AWS', hosting: true }] },
  geo_policy: { geoIp: GEO_IP },
  ip_reputation: { feed: [{ cidr: '45.155.205.0/24', score: 95 }] },
  tor_exit_node: { exitNodes: ['185.220.101.1'] },
  absolute_uri_request: HOSTS,
  host_header_injection: HOSTS,
  websocket_origin: ORIGINS,
  endpoint_quota: { costs: [{ route: '/api/search', cost: 5 }] },
  open_redirect: HOSTS,
};

function request(overrides: Partial<NormalizedRequest> = {}): NormalizedRequest {
  return {
    requestId: 'r1', tenantId: TENANT, endpoint: 'GET /api/items', clientIp: '203.0.113.7', query: {}, headers: {}, body: undefined,
    requestHash: 'h', fields: [], files: [], timestamp: Date.now(), ...overrides,
  };
}

const fresh = (namespace = 'test') => new ToolState(new MemoryToolState().stores, namespace);
const build = (id: ToolId, config: unknown, state = fresh()) => createTool(id, config, state);
const verdictOf = async (tool: Tool<ToolContextType>, context: unknown) => (await tool.run(context as never)).verdict;

describe('tool registry', () => {
  it.each(TOOL_IDS)('%s is implemented as its contract describes', (id) => {
    const contract = toolContract(id);
    const tool = build(id, REQUIRED[id] ?? {});
    expect(tool.metadata).toEqual({
      id: contract.id,
      displayName: contract.displayName,
      category: contract.category,
      contextType: contract.contextType,
    });
  });

  it('rejects configurations that break a contract', () => {
    expect(() => build('rate_limit', { limit: 0 })).toThrow();
    expect(() => build('rate_limit', { limit: 10, burst: 5 })).toThrow(); // unknown setting
    expect(() => build('honeypot_field', {})).toThrow(); // required setting
    expect(() => build('brute_force', { attempts: { suspicious: 40, block: 30 } })).toThrow();
    expect(() => build('regex_pattern', { pattern: '(' })).toThrow();
    expect(() => build('geo_policy', { geoIp: [{ cidr: '999.1.1.0/24', country: 'GB', city: 'x', lat: 0, lon: 0 }] })).toThrow();
    expect(() => build('string_length', { operator: '==', length: 3 })).toThrow();
    expect(() => build('string_length', { operator: '<', length: 3, maxLength: 5 })).toThrow();
  });

  it('runs tools with the configuration they were given', async () => {
    const rateLimit = build('rate_limit', { limit: 2, windowMs: 60_000 });
    const verdicts = [];
    for (let attempt = 0; attempt < 3; attempt++) verdicts.push(await verdictOf(rateLimit, request()));
    expect(verdicts).toEqual(['SAFE', 'SAFE', 'POLICY_VIOLATION']);

    const filled = request({ fields: [{ name: 'faxNumber', value: '123', type: 'string', location: 'body' }] });
    expect(await verdictOf(build('honeypot_field', { fields: ['faxnumber'] }), filled)).toBe('POLICY_VIOLATION');
    expect(await verdictOf(build('honeypot_field', { fields: ['website'] }), filled)).toBe('SAFE');
  });

  it.each([
    ['<', 5, ['abcd'], ['abcde', 'abcdef']],
    ['<=', 5, ['abcd', 'abcde'], ['abcdef']],
    ['>', 5, ['abcdef'], ['abcd', 'abcde']],
    ['>=', 5, ['abcde', 'abcdef'], ['abcd']],
  ])('string_length requires length %s %i', async (operator, length, allowed, rejected) => {
    const tool = build('string_length', { operator, length });
    const field = (value: string) => ({ name: 'name', value, type: 'string', location: 'body' });
    for (const value of allowed) expect(await verdictOf(tool, field(value)), value).toBe('SAFE');
    for (const value of rejected) expect(await verdictOf(tool, field(value)), value).toBe('POLICY_VIOLATION');
    expect((await tool.run(field(rejected[0]) as never)).evidence).toEqual({ length: rejected[0].length, required: `length ${operator} ${length}` });
  });

  it('string_length still takes the v1 inclusive bounds', async () => {
    const tool = build('string_length', { minLength: 2, maxLength: 3 });
    const field = (value: string) => ({ name: 'name', value, type: 'string', location: 'body' });
    expect(await Promise.all(['a', 'ab', 'abc', 'abcd'].map(value => verdictOf(tool, field(value)))))
      .toEqual(['POLICY_VIOLATION', 'SAFE', 'SAFE', 'POLICY_VIOLATION']);
  });

  it('keeps cross-request state in the store, per tenant and per step', async () => {
    const memory = new MemoryToolState();
    const config = { limit: 1, windowMs: 60_000 };
    const first = build('rate_limit', config, new ToolState(memory.stores, 'step-a'));
    // a second proxy process (or a restart) running the same step shares the state
    const sameStep = build('rate_limit', config, new ToolState(memory.stores, 'step-a'));
    const otherStep = build('rate_limit', config, new ToolState(memory.stores, 'step-b'));

    expect(await verdictOf(first, request())).toBe('SAFE');
    expect(await verdictOf(sameStep, request())).toBe('POLICY_VIOLATION');
    expect(await verdictOf(otherStep, request())).toBe('SAFE');
    expect(await verdictOf(first, request({ tenantId: OTHER_TENANT }))).toBe('SAFE');

    const replay = build('duplicate_request', {}, new ToolState(memory.stores, 'dup'));
    expect(await verdictOf(replay, request({ requestId: 'a' }))).toBe('SAFE');
    expect(await verdictOf(replay, request({ requestId: 'b' }))).toBe('SUSPICIOUS');
  });

  it('reports ERROR, never SAFE, when the state store is unavailable', async () => {
    const memory = new MemoryToolState();
    const tool = build('rate_limit', {}, new ToolState(memory.stores, 'step')) as Tool<ToolContextType.Full>;
    memory.down = true;
    const [result] = await new Runner().run(request(), [{ tool }]);
    expect(result).toMatchObject({ tool: 'rate_limit', status: 'ERROR', verdict: 'ERROR' });
  });

  it('publishes every contract in docs/tool-registry.json (run `npm run tools:registry` after changing one)', () => {
    const published = JSON.parse(readFileSync(resolve(__dirname, '../../docs/tool-registry.json'), 'utf8'));
    expect(published).toEqual(JSON.parse(JSON.stringify(toolRegistryDocument())));
  });
});
