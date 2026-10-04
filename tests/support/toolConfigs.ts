import type { ToolId } from '../../source/shared/contracts/tools';

const ORIGINS = { allowedOrigins: ['https://example.com'] };
const HOSTS = { allowedHosts: ['example.com'] };
const GEO_IP = [{ cidr: '81.2.69.0/24', country: 'GB', city: 'London', lat: 51.51, lon: -0.13 }];

/** The smallest valid configuration of every tool with required settings; all others run on defaults. */
export const REQUIRED: Partial<Record<ToolId, Record<string, unknown>>> = {
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
