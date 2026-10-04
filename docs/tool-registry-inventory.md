# Proxy tool registry

The proxy executes the tools of `tessera.tools/v3`: every tool in
`source/core/static-analysis/tools`, 150 in total. Each one has a **tool
contract** in [`source/shared/contracts/tools`](../source/shared/contracts/tools):
its id, display name, category, context type, description and a Zod schema of
its configuration. The proxy and the dashboard compiler validate policies
against the same contracts.

[`docs/tool-registry.json`](tool-registry.json) lists every tool with its
metadata and its configuration as JSON Schema (the input side: settings with a
default are optional and show that default). It is generated from the
contracts, and a test fails when it is out of date:

```sh
npm run tools:registry
```

## Policy steps

A signed bundle configures a tool per step. In a `tessera.bundle/v3` the steps
sit in three scopes: `global`, `environment` and each endpoint. The first two
run on every request, and when a tool and target repeat, the endpoint step
wins, then the environment one.

```json
{ "toolId": "brute_force", "contextType": "full", "config": { "attempts": { "suspicious": 5, "block": 20 } } }
{ "toolId": "enum_validation", "contextType": "field", "target": "body.currency", "config": { "values": ["PLN", "EUR"] } }
{ "toolId": "file_size", "contextType": "file", "target": "avatar", "config": { "maxBytes": 1048576 } }
{ "toolId": "string_length", "contextType": "field", "target": "body.username", "config": { "operator": "<=", "length": 32 } }
```

The proxy rejects the whole bundle, and keeps its last known good one, when a
step names an unknown tool, uses another context type than the contract, has a
missing or malformed target (`body.*`/`query.*` for field tools, the upload
field for file tools, none for whole-request tools; `body.*`, `query.*` and
`*` only in the global and environment scopes) or a configuration that
breaks the contract, including unknown settings. Defaults are applied when the
tool is built, so the signed configuration stays exactly as the dashboard sent
it.

Tools that look across requests (rate limits, brute force, replay and
duplicate detection, and so on; 21 in total) keep their state in Redis, under
`tessera:{tenantId}:tools:{toolId}:{step}:`. The step part is a hash of the
endpoint (or the global or environment scope) and the step, so two steps never share state, an unchanged step keeps
its windows across bundle updates and restarts, and every proxy process of the
tenant counts together. Redis expires the state on its own. While Redis is
unavailable these tools report `ERROR`, which the tenant's
static-analysis failure behavior decides; they never fall back to `SAFE`.

Older bundles are still accepted: `tessera.tools/v1` ones may only use
`string_length`, and `tessera.tools/v2` ones every tool except those added in
v3 (`php_object_injection`). The proxy advertises all three registries in
`Tessera-Tool-Registries` and in its heartbeat.

## What is configuration and what is not

Configuration is everything that depends on the protected application or on
the operator's risk appetite: limits and thresholds, time windows, route
filters, allowlists (hosts, origins, redirect targets, MIME types), field
names, secrets and threat-intelligence data. Before v2 these were constants or
mock data for a fictional `example.com` shop in `shared/mockConfig.ts`, which
is now removed.

Not configuration: detection signatures (SQL, XSS, shell syntax and the like),
safety caps that bound the work a tool does on hostile input (scan lengths,
decode rounds, node counts), and the protocol rules HTTP itself defines. They
are fixed by the registry version. Tools whose only content is signatures take
an empty configuration (`{}`).

Settings that describe the application have no default and must be set:

| Tool | Required settings |
| --- | --- |
| `additional_properties`, `array_uniqueness`, `required_fields`, `openapi_conformance` | the endpoint's declared body properties / query parameters |
| `enum_validation`, `format_validation`, `regex_pattern`, `type_coercion` | the rule for the targeted field |
| `integer_range` | at least one bound |
| `string_length` | `operator` (`<`, `>`, `<=`, `>=`) and `length`: the comparison the value's length must satisfy. The v1 form `{ minLength, maxLength }` is still accepted |
| `json_schema` | the JSON Schema |
| `honeypot_field` | the hidden form fields |
| `referer_anomaly`, `csrf`, `websocket_origin` | the application's origins |
| `absolute_uri_request`, `host_header_injection`, `open_redirect` | the allowed hosts |
| `cookie_tampering` | the cookie-signing secret and signed cookie names |
| `jwt_validation` | the issuer's public key |
| `oauth_flow_validation` | authorize and/or callback routes |
| `endpoint_quota` | route costs |
| `impossible_travel`, `geo_policy` | a geo-IP table |
| `datacenter_asn`, `ip_reputation`, `tor_exit_node` | the ASN table, reputation feed or exit-node list |

Tools that used to apply to a mock route group (login, privileged, catalog,
...) take an optional `routes` filter. Omitted, the check covers every
endpoint the step is attached to, which is the normal way to scope it.

Two consequences to keep in mind when compiling policies:

- `cookie_tampering.secret` travels inside the signed bundle, which is signed
  but not encrypted, and is cached on the proxy's disk (mode 0600).
- Geo-IP, ASN, reputation and Tor tables are bundle data with size limits
  (100,000 entries); they only change with a new bundle.
