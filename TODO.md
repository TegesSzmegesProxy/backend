# Tessera TODO

Last synced with codebase: 2026-10-03 (HEAD `861b8a2` + uncommitted environment-analyzer and ingress work)

## Current Status

The architecture now has **three deployables in one repo** (see `control-plane.md`):

| Deployable | Runs at | Modules | Entry point (target) |
|---|---|---|---|
| Proxy (data plane) | client server, behind Nginx | `edge`, `core`, `feedback`, `shared` | `source/bootstrap-proxy.ts` |
| Control plane | hosted by us | `control`, AI part of `analysis`, `shared` | `source/bootstrap-control.ts` |
| Collector | client CI / CLI | collection + redaction part of `analysis`, `shared` | `source/collector.ts` |

The proxy pulls a **signed, versioned `ActiveBundle`** per tenant from the control plane at startup, verifies it, and keeps it as last known good. The admin API, tenant registry, API keys, policy versions, compilation and activation all live in the control plane, not in the proxy. Most of the previous plan assumed one process and has been reassigned below.

Done:
- **Tooling:** strict `tsconfig.json` with `@tessera/*`, ESLint, Prettier, vitest. `npx vitest run` passes (32 tests, environment analyzer only). `zod` is installed.
- **Storage** ([source/shared/storage/](source/shared/storage/)): `MongoStorage.tenantDb(tenantId)` (one DB per tenant), `RedisStorage`/`TenantRedis` (`tessera:{tenantId}:` prefix, `pushRecent`/`recent`), `MongoRepository<T>`, `assertTenantId`.
- **Broker** ([source/shared/broker/connect.ts](source/shared/broker/connect.ts)): Redis pub/sub. Under the new architecture it is control-plane-internal only.
- **Bootstrap** ([source/bootstrap.ts](source/bootstrap.ts)): Mongo required, Redis/broker optional, graceful shutdown. Single entry point for now.
- **Normalizer** ([source/edge/normalizer/normalizer.ts](source/edge/normalizer/normalizer.ts)): flattens JSON body + query into dotted `fields`, computes `requestHash`. No files, path params or headers as fields; takes a `FastifyRequest`.
- **Static analysis:** `Tool<C>` ([Tool.ts](source/core/static-analysis/shared/Tool.ts)), synchronous sequential `Runner` ([Runner.ts](source/core/static-analysis/runner/Runner.ts)) that turns a throw into `ERROR`, `Aggregator` ([Aggregator.ts](source/core/static-analysis/aggregator/Aggregator.ts)), one tool `stringLength` (hard-coded config).
- **Ingress** ([source/edge/ingress/server.ts](source/edge/ingress/server.ts)): catch-all route runs normalizer → runner (hard-coded plan) → aggregator, forwards SAFE requests with `@fastify/reply-from` to `UPSTREAM_URL`. Prototype only.
- **Collector – environment analysis** ([source/analysis/environment/](source/analysis/environment/)): `EnvironmentAnalyzer` running nmap, nuclei, trivy, httpx and lynis through an injectable `CommandRunner`; per-tool timeouts; a failing/missing tool is recorded as `failed`, not thrown; parsers + analyzer tests with fixtures; `npm run analyze:mock`.

Known defects in existing code:
- `source/edge/upstream/upstream.ts` does not compile (`resolve(result: )`), so `tsc --noEmit` fails.
- **Aggregator is order-dependent:** it returns on the first `POLICY_VIOLATION` or `ERROR` it meets, so the result depends on tool order and violates the documented `ERROR > POLICY_VIOLATION > SUSPICIOUS > SAFE` priority. See T00 point 7.
- **Runner silently passes missing fields:** a field step whose target is absent from the request produces no result, so the request aggregates to SAFE. A missing required field must be detectable (T25).
- Ingress maps `POLICY_VIOLATION` → 400 (must be 403 with only `requestId`), `ERROR` → 500 (must follow tenant failure behavior), and `SUSPICIOUS` → 202 without forwarding or calling JEV. The route only accepts GET/POST/PUT/PATCH/DELETE.
- Ingress still loads env via `@fastify/env` (from `source/.env`) and creates a **second** `Broker`. The proxy should not use the broker at all.
- `bootstrap.ts` creates a `tenantsDb` `MongoStorage` that is never connected or used.
- `Normalizer.hashFields` concatenates names and values without separators, so different requests can collide (`{ab:"c"}` vs `{a:"bc"}`). This matters once the hash keys the verdict cache.
- `stringLength.ts` and the ingress use deep imports (`@tessera/x/y/File`), but the vitest alias maps every `@tessera/x` to `source/x/index.ts`.
- `NormalizedRequest.timestamp` is `number`; `contracts.md` says ISO `string`.
- Both `@fastify/http-proxy` and `@fastify/reply-from` are installed; only `reply-from` is used.
- `eslint`, `typescript-eslint`, `@eslint/js` and `vitest` are in `dependencies`; `npm test` is still a placeholder.
- Stray file: `source/shared/logger/done.txt`.

Conventions:
- Paths are real `source/...` paths. Each module exposes its public API through `index.ts`.
- HTTP server: **Fastify** in all deployables (skill text still says Express; T00 point 5).
- Proxy and control plane never import each other's modules. Shared code is contracts and generic infra only, enforced by ESLint `no-restricted-imports`.
- Tool **ids and config schemas** live in `shared/contracts` so the control-plane compiler and the proxy registry validate against the same definitions. Tool implementations stay in the proxy.
- Proxy and control plane have separate MongoDB and Redis instances. Proxy Mongo holds only last-known-good bundles and adaptive state.
- Tenant identity on the control plane comes from the authenticated key/session, never from request parameters.

Owners:
- **Antek:** collector / environment analysis, analysis upload, policy pipeline (AI analysis → generation → compilation).
- **Dawid:** static-analysis pipeline (runner, aggregator, tools).
- Unassigned: foundation, control-plane core and distribution, proxy runtime.

**Milestone P0 — signed-bundle runtime slice:** a tenant and policy are created through the control-plane admin API and activated; the control plane signs the bundle; the proxy pulls and verifies it and enforces a request end-to-end (normalize → static analysis → sampling → JEV → decision → forward or 403).

---

## TODO

### 0. Decisions

### [T00] [P0] [TODO] Remaining open decisions
- Description: To be decided by the project owner (not invented) and recorded in the references:
  1. **JEV API:** endpoint, auth and wire format. Blocks T30.
  2. **Tessera-down behavior:** Nginx fails open (route to upstream) or closed (503)? Per tenant?
  3. **Unknown endpoint:** confirm pass-through as default and name the `runtimeConfig` key.
  4. **No valid bundle at proxy startup** (control plane unreachable, no last known good): refuse to start, or skip that tenant and apply which behavior?
  5. **HTTP stack:** change `SKILL.md` and `system.md` from Express to Fastify.
  6. **`NormalizedRequest.timestamp`:** `number` or ISO `string`?
  7. **Aggregator priority:** keep `ERROR > POLICY_VIOLATION`, or let a definite `POLICY_VIOLATION` win so an `ERROR` with a fail-open setting cannot override a known violation?
  8. **Dashboard auth:** organization-level auth for dashboard users (open in `control-plane.md`). For the hackathon, is a single platform admin bearer key enough?
  9. **Active scanning in the collector:** nuclei sends active payloads and nmap scans ports. Who confirms target ownership, and is it opt-in per run? `analysis.md` lists Syft/Trivy/Nmap; the code also runs nuclei, httpx and lynis.
  10. **Local development without a control plane:** may the proxy load a signed bundle from a file (still verified), or must dev always run both deployables?
- Files/modules: `.claude/skills/project architectuer/SKILL.md`, `references/{system,runtime,contracts,operations,control-plane,analysis,static-analysis}.md`
- Depends on: —
- Acceptance criteria: Each point has a written answer in the references, and no two reference files contradict each other.

### 1. Foundation (shared)

### [T01] [P0] [PARTIAL] Tooling: build, lint, test
- Done: tsconfig, eslint, prettier, vitest config, `tests/` with environment analyzer tests, `zod`.
- Description:
  - Fix the compile error in `source/edge/upstream/upstream.ts`.
  - Scripts: `build` (`tsc --noEmit`), `lint`, `test` (`vitest run`).
  - Fix the vitest alias so deep imports resolve to the file, falling back to `index.ts` — or ban deep imports and import through module `index.ts` only.
  - Move lint/test packages to `devDependencies`; remove `@fastify/http-proxy` if `reply-from` stays.
- Files/modules: `package.json`, `vitest.config.ts`, `eslint.config.ts`, `source/edge/upstream/`
- Depends on: —
- Acceptance criteria: `npm run build`, `npm run lint` and `npm test` exit 0. A test importing `StringLength` runs.

### [T02] [P0] [TODO] Deployable split and import boundaries
- Description:
  - Replace `source/bootstrap.ts` with `bootstrap-proxy.ts` (edge/core/feedback) and `bootstrap-control.ts` (control/analysis), plus a `collector.ts` CLI entry.
  - Scripts `dev:proxy`, `dev:control`, `collector`.
  - ESLint `no-restricted-imports`: proxy modules cannot import `control`/`analysis`; control cannot import `edge`/`core`/`feedback`; collector code cannot import either runtime.
  - Remove the broker and the unused `tenantsDb` from the proxy bootstrap; the broker belongs to control only.
- Files/modules: `source/bootstrap-*.ts`, `source/collector.ts`, `eslint.config.ts`, `package.json`
- Depends on: T01
- Acceptance criteria: Both servers start independently. A test import from `core` into `control` fails lint.

### [T03] [P0] [PARTIAL] Typed configuration per deployable + docker-compose
- Done: `.env` loading, `requireEnv`, `REDIS_URL`/`MONGO_URL`/`MONGO_DB_NAME`, `.env.example`.
- Description:
  - Zod-validated config per deployable, validated before connecting:
    - **Proxy:** `PROXY_PORT`, `CONTROL_PLANE_URL`, `DEPLOYMENT_KEY`, `BUNDLE_PUBLIC_KEY`, `TENANT_IDS`, `JEV_URL`, `JEV_API_KEY`, `JEV_TIMEOUT_MS`, `MAX_BODY_BYTES`, `TRUSTED_PROXIES`, `LOG_DIR`.
    - **Control:** `CONTROL_PORT`, `ADMIN_API_KEY` (pending T00.8), `BUNDLE_PRIVATE_KEY`, AI provider key(s).
    - **Collector:** `CONTROL_PLANE_URL`, `COLLECTOR_KEY`.
  - Remove `@fastify/env` and the second `Broker` from the ingress; ingress receives config from bootstrap. `UPSTREAM_URL` goes away (it comes from the bundle).
  - `docker-compose.yml`: proxy Mongo + Redis, control Mongo + Redis (separate instances), and a tiny sample upstream app.
- Files/modules: `source/shared/config/`, `source/edge/ingress/server.ts`, `docker-compose.yml`, `.env.example`
- Depends on: T02
- Acceptance criteria:
  - A missing required variable exits non-zero and names the variable.
  - `docker compose up` starts all services and both deployables connect.

### [T04] [P0] [PARTIAL] Shared contracts as Zod schemas
- Done: TS interfaces `NormalizedRequest`, `RequestField`, `RequestFile`; `ToolResult` in `Tool.ts`; `StaticVerdict` in `Aggregator.ts`.
- Description:
  - Zod schemas with inferred types in `shared/contracts` for everything that crosses a deployable or module boundary: request contracts, `Policy`, `EndpointPolicy`, `FieldPolicy`, `ToolConfig`, `RuntimeConfig` (routing, failure behavior, thresholds + locks, `unknownEndpointBehavior`, sampling bounds), `ActiveBundle` (with `schemaVersion`), and the analysis upload package.
  - **Tool catalog:** tool ids and per-tool config schemas in `shared/contracts/tools` (no implementations).
  - Module-owned contracts stay in their module: `ToolResult`/`StaticVerdict` (static-analysis), `JevInput`/`JevResult` (jev), `Decision` (decision), `AdaptiveState` (feedback).
  - Canonical JSON serialization helper for hashing and signing.
- Files/modules: `source/shared/contracts/`, `source/core/{static-analysis,jev,decision}/contracts.ts`
- Depends on: T01, T00 (point 6)
- Acceptance criteria:
  - `JevResult` with `score: 7`, missing `confidence` or unknown `verdict` is rejected.
  - `ActiveBundle` without `tenantId`, `version` or `signature` is rejected.
  - Canonical JSON is key-order independent.

### 2. Control plane (hosted)

### [T10] [P0] [TODO] Organizations, tenants and runtime config
- Description:
  - Platform DB: `organizations` and `tenants` (`tenantId`, `organizationId`, routing host/IP + `pathPrefix`, `upstreamUrl`, failure behavior, thresholds with `locked`, `unknownEndpointBehavior`, sampling bounds).
  - No implicit failure-behavior defaults: missing fields fail validation.
  - Tenant data in `tenantDb(tenantId)`; every query is also organization-scoped.
- Files/modules: `source/control/tenants/` (new)
- Depends on: T03, T04
- Acceptance criteria:
  - A missing failure-behavior field fails validation.
  - Org A cannot read or modify org B's tenant.

### [T11] [P0] [TODO] API keys
- Description:
  - Deployment keys (scoped to a set of tenants, pull only) and collector keys (scoped to tenants, upload only).
  - Store only a hash + metadata (id, org, tenants, scopes, created/revoked). Plaintext shown once.
  - Revocation; an auth hook resolves key → `{organizationId, tenantIds, scopes}`.
- Files/modules: `source/control/api-keys/` (new)
- Depends on: T10
- Acceptance criteria:
  - Plaintext is never stored.
  - A revoked key gets 401; a collector key cannot pull bundles; a deployment key cannot upload.

### [T12] [P0] [TODO] Policy versions and activation
- Description:
  - Versions in `tenantDb`: human-readable text, structured policy, compiled toolchain; `version` = hash of canonical content; insert-only.
  - Active pointer per tenant, updated atomically. Only compiled versions can be activated.
- Files/modules: `source/control/policy-store/` (new)
- Depends on: T04, T10
- Acceptance criteria:
  - Same content → same `version`; updating a version is rejected.
  - Tenant A cannot activate tenant B's version.

### [T13] [P0] [TODO] Admin API (minimal)
- Description:
  - Fastify on `CONTROL_PORT`, auth per T00.8.
  - Create organization/tenant, update runtime config, create/revoke API keys, import a structured policy (validate → store, no activation), activate a version.
  - Thin controllers over T10–T12.
- Files/modules: `source/control/policy-api/`
- Depends on: T10, T11, T12
- Acceptance criteria:
  - Unauthenticated requests get 401 on every route.
  - Invalid policy → 400 and nothing stored; valid policy returns its `version`.

### [T14] [P0] [TODO] Bundle builder and Ed25519 signing
- Description:
  - On activation, build `ActiveBundle` from runtime config + compiled policy, sign canonical `{schemaVersion, tenantId, version, runtimeConfig, policy}` with `BUNDLE_PRIVATE_KEY`, store it.
  - Script to generate a key pair for dev.
- Files/modules: `source/control/distribution/` (new), `scripts/gen-bundle-keys.ts`
- Depends on: T12, T04
- Acceptance criteria: The signature verifies with the public key; any change to config or policy breaks it.

### [T15] [P0] [TODO] Distribution API
- Description: `GET /v1/tenants/{tenantId}/active-bundle` with a deployment key; `ETag: version`; `If-None-Match` → 304; tenant outside the key's set → 403.
- Files/modules: `source/control/distribution/`
- Depends on: T11, T14
- Acceptance criteria: Key for tenant A gets 403 for tenant B; unchanged version returns 304.

### [T16] [P1] [TODO] Analysis upload intake
- Description: `POST /v1/tenants/{tenantId}/analysis-context` with a collector key; Zod-validate the package; store tenant-scoped with `sourceRevision`; emit `AnalysisContextReceived`.
- Files/modules: `source/control/analysis-intake/` (new)
- Depends on: T11, T04, T17
- Acceptance criteria: Wrong-tenant key → 403; invalid package → 400; a valid upload is stored and emits one event.

### [T17] [P1] [PARTIAL] Events: envelope, outbox, inbox (control-internal)
- Done: Redis pub/sub `Broker`.
- Description: Versioned envelope `{eventId, eventType, version, tenantId, aggregateId, occurredAt, payload}`; Mongo outbox written with the state change and relayed via `Broker`; Mongo inbox (`consumer + eventId` unique) for idempotent handlers; retry then failure event. Never crosses the network.
- Files/modules: `source/control/events/`
- Depends on: T02
- Acceptance criteria: Duplicate delivery runs once; crash between commit and publish still publishes after restart; event without `tenantId` rejected.

### [T18] [P1] [TODO] Policy compiler and toolchain generator
- Description: Compile a structured policy into a toolchain using only catalog tool ids and validated configs (T04); infer default tools per field type. Saga: `PolicyGenerated|PolicyImported → PolicyCompiled | PolicyCompilationFailed`.
- Files/modules: `source/control/policy-compiler/`, `source/control/toolchain-generator/`
- Depends on: T12, T17, T04
- Owner: Antek
- Acceptance criteria: Unknown tool → `PolicyCompilationFailed`, active unchanged; string field with maxLength gets a schema tool; duplicate event → one compiled version.

### [T19] [P1] [TODO] Approval and activation saga
- Description: Approve/reject → `PolicyApproved`/`PolicyRejected`; activation sets the pointer, builds and signs the bundle (T14), emits `PolicyActivated`. Approval can be required for generated and/or edited policies.
- Files/modules: `source/control/policy-store/`, `source/control/policy-api/`
- Depends on: T18, T13, T14
- Acceptance criteria: Uncompiled/failed versions cannot be activated; duplicate `PolicyApproved` is a no-op.

### [T1A] [P1] [TODO] Telemetry intake
- Description: `POST /v1/telemetry` with a deployment key: batched verdict counts, recent BLOCK summaries (redacted), active version, degraded state, "restart required". Stored per tenant for the dashboard.
- Files/modules: `source/control/telemetry/` (new)
- Depends on: T11
- Acceptance criteria: Telemetry for a tenant outside the key's set is rejected.

### 3. Proxy (data plane)

### [T20] [P0] [TODO] Bundle client: pull, verify, last known good
- Description:
  - At startup, for each tenant in `TENANT_IDS`: pull the bundle, verify (signature, expected tenant, supported `schemaVersion`, schema, every tool id in the proxy registry + config valid), persist atomically as last known good in proxy Mongo.
  - Control unreachable/erroring → load last known good, log degraded. Verification failure → reject, keep last known good. Neither → T00.4.
  - P1: poll with `If-None-Match`, report "restart required" only (never hot-swap).
- Files/modules: `source/edge/bundle-client/` or `source/core/policy/` (new)
- Depends on: T04, T15, T25 (registry), T00 (point 4)
- Acceptance criteria: Tampered, wrongly signed, unknown-tool and wrong-tenant bundles are rejected and last known good is used; with control down the proxy starts on last known good.

### [T21] [P0] [TODO] Runtime snapshot and tenant resolver
- Description: Build a frozen per-tenant snapshot from verified bundles; resolve (host, path) → tenant by longest prefix from `runtimeConfig` routing; each request holds one snapshot reference.
- Files/modules: `source/core/tenancy/`, `source/core/policy/`
- Depends on: T20
- Acceptance criteria: Prefixes `/a` and `/a/b` resolve correctly; unmatched host → "no tenant"; snapshot mutation throws; a request reads exactly one `policyVersion`.

### [T22] [P0] [TODO] Endpoint matcher
- Description: Match `method + path` against endpoint templates (`/users/:id`), exact before parameterized; return `EndpointPolicy` + path params; unmatched → unknown endpoint.
- Files/modules: `source/core/policy/endpoint-matcher.ts`
- Depends on: T04
- Acceptance criteria: Tests for precedence, method mismatch, and documented trailing-slash behavior.

### [T23] [P0] [PARTIAL] Ingress: raw body and unchanged forwarding
- Done: catch-all route, `@fastify/reply-from` forwarding to a single `UPSTREAM_URL`.
- Description:
  - All HTTP methods; raw `Buffer` parser for every content type with `MAX_BODY_BYTES`; original bytes kept and forwarded unchanged to the tenant's `upstreamUrl` from the snapshot.
  - Upstream error/timeout → 502/504.
  - Remove the inline verdict `switch`: ingress only calls the decision orchestrator (T31) and forwards or returns the fixed 403.
- Files/modules: `source/edge/ingress/`, `source/edge/upstream/`
- Depends on: T03, T21
- Acceptance criteria: Byte-identical bodies (JSON, urlencoded, multipart, binary), query and headers (except hop-by-hop) reach the sample upstream; upstream down → 502.

### [T24] [P0] [PARTIAL] Normalizer completion
- Done: JSON body + query flattening into dotted fields with types, `requestHash`.
- Description:
  - Take a transport-neutral raw request (method, path, query, headers, raw body, remote IP) instead of `FastifyRequest`.
  - Parse JSON, urlencoded and multipart from the raw buffer; add path params and relevant headers as fields (`location: path|header`).
  - Files: `field`, `filename`, `contentType`, `size`, `magicBytes` (hex of first N bytes).
  - Client IP from `X-Forwarded-For`/`X-Real-IP` only from `TRUSTED_PROXIES`.
  - Unparseable body → normalization error, not an empty body.
  - Collision-free `requestHash` (hash canonical JSON of fields, not concatenation).
- Files/modules: `source/edge/normalizer/`
- Depends on: T04, T23
- Acceptance criteria: Nested JSON flattened; PNG/PDF magic bytes correct; spoofed `X-Forwarded-For` ignored; malformed JSON → error; `{ab:"c"}` and `{a:"bc"}` hash differently.

### [T25] [P0] [PARTIAL] Tool registry and Runner from policy
- Owner: Dawid
- Done: `Tool<C>`, `field|file|full` contexts, `Runner` executing a hand-built plan, throw → `ERROR`.
- Description:
  - Tool registry: catalog id (T04) → implementation factory taking validated config.
  - Build the execution plan from `EndpointPolicy` (`requestTools` + `fields[].tools`) instead of the hard-coded list.
  - Missing target field: a step for a required field must produce a result (via the `required` schema tool), never silently disappear.
  - Make tools async with a per-tool timeout; timeout → `ERROR`. Run independent tools concurrently.
  - P1: declared dependencies (DAG), cycle rejected.
  - Unknown tool id → `ERROR` (and rejected earlier at bundle verification).
- Files/modules: `source/core/static-analysis/{shared,runner,tools/index.ts}`
- Depends on: T04
- Acceptance criteria: Plan built from a policy fixture; throwing and timing-out tools → `ERROR`; a field tool receives only its field; a missing required field → `POLICY_VIOLATION`.

### [T26] [P0] [PARTIAL] Aggregator fix and tests
- Owner: Dawid
- Done: SAFE / SUSPICIOUS / POLICY_VIOLATION / ERROR aggregation.
- Description: Make the result order-independent using the priority decided in T00.7; collect all non-SAFE results as evidence (no raw SAFE output); move `StaticVerdict` to static-analysis contracts.
- Files/modules: `source/core/static-analysis/aggregator/`
- Depends on: T00 (point 7)
- Acceptance criteria: Table-driven tests over every combination and every order give the same verdict; all-SAFE → SAFE.

### [T27] [P0] [PARTIAL] Schema and resource tools
- Owner: Dawid
- Done: `stringLength` (hard-coded).
- Description: Config-driven `stringLength` (`min`/`max`); field tools for type, required, numeric range, regex/format, enum; request tools for body size, field count, nesting depth, array length. Each tool's config schema lives in the shared catalog.
- Files/modules: `source/core/static-analysis/tools/{schema,resource}/`, `source/shared/contracts/tools/`
- Depends on: T25
- Acceptance criteria: Wrong type / missing required / oversized body → `POLICY_VIOLATION`; valid → SAFE; no hard-coded thresholds.

### [T28] [P0] [TODO] Injection, URL and file-magic tools
- Owner: Dawid
- Description: Injection patterns (SQLi, XSS, command, path traversal, template) with configurable action; URL scheme allow-list and private/loopback/link-local/metadata IPs on literal parse (no DNS); file magic vs declared type and allowed types.
- Files/modules: `source/core/static-analysis/tools/{injection,url,file}/`
- Depends on: T25
- Acceptance criteria: `' OR 1=1 --`, `<script>`, `../../etc/passwd`, `http://169.254.169.254/` flagged; `.png` with PDF magic → `POLICY_VIOLATION`; benign → SAFE.

### [T29] [P0] [TODO] Sampling with secure randomness
- Description: `shouldSample(config)` with `crypto.randomInt`, N clamped to `[minN, maxN]`; only SAFE consults sampling; SUSPICIOUS always goes to JEV.
- Files/modules: `source/core/sampling/`
- Depends on: T04
- Acceptance criteria: N=0 never, N=100 always, N=10 → 10% ± 1% over 100k; no `Math.random`.

### [T30] [P0] [BLOCKED on T00.1] JEV client
- Description: Port `classify(JevInput) → JevResult`; HTTP adapter with timeout, env API key, Zod-validated response; invalid/late → `JevUnavailable`; deterministic stub for tests.
- Files/modules: `source/core/jev/`
- Depends on: T04, T00 (point 1)
- Acceptance criteria: Malformed or late response → `JevUnavailable`; valid parses; adapter chosen by config.

### [T31] [P0] [TODO] Decision orchestrator
- Description:
  - `tenant → snapshot → endpoint → normalize → static analysis → sampling → JEV → thresholds → Decision`, without Fastify types.
  - Tenant failure behavior for normalization errors, static `ERROR` and JEV unavailable.
  - ATTACK only when `score > maliciousScoreThreshold && confidence > confidenceThreshold`; else ALLOW.
  - Unknown endpoint per `runtimeConfig` (T00.3).
- Files/modules: `source/core/decision/`
- Depends on: T21, T22, T24, T26, T29, T30
- Acceptance criteria: Table-driven ALLOW/BLOCK test for POLICY_VIOLATION (no JEV), ERROR, SUSPICIOUS + ATTACK/BENIGN, SAFE unsampled (no JEV), SAFE sampled + ATTACK, JEV unavailable under each setting, low confidence; every `Decision` carries `policyVersion`; no cross-tenant policy use.

### [T32] [P0] [TODO] End-to-end slice
- Description: Wire ingress → orchestrator → forward or fixed 403 `{requestId}` (no evidence leaked, nothing sent upstream).
- Files/modules: `source/edge/ingress/`, `source/bootstrap-proxy.ts`, `tests/e2e/`
- Depends on: T13, T15, T20, T23, T31
- Acceptance criteria: With docker-compose, both deployables and the JEV stub: tenant + policy created and activated via the control-plane admin API; proxy pulls and verifies the bundle; benign request reaches the upstream; SQLi gets 403 and the upstream receives nothing; two tenants are enforced independently; stopping the control plane does not change enforcement.

### [T33] [P1] [TODO] Structured decision logging
- Description: pino JSON logs under `LOG_DIR` with tenant, endpoint, policyVersion, static verdict, sampled, JEV verdict/score/confidence, thresholds, action, failure state, requestId; redact values, bodies, `Authorization`, `Cookie`; replace `console.*`.
- Files/modules: `source/shared/logger/`, `source/core/decision/`
- Depends on: T31
- Acceptance criteria: Log line parses with all keys; secrets and body values never appear.

### [T34] [P1] [PARTIAL] Request history (last 3 per tenant + client IP)
- Done: `TenantRedis.pushRecent`/`recent`.
- Description: Push a compact summary under `hist:{clientIp}` after each decision; read into `JevInput.recentRequests`; Redis error → empty history + log.
- Files/modules: `source/core/history/`
- Depends on: T31
- Acceptance criteria: Only last 3 returned; tenants isolated per IP; Redis down → decisions still correct.

### [T35] [P1] [TODO] Adaptive state and sampling controller
- Description: Persist `AdaptiveState` (tenant + endpoint EWMA, α) in proxy Mongo; update only from JEV ATTACK/BENIGN; flush periodically and on shutdown. Controller computes endpoint N from endpoint and tenant EWMA (endpoint weighted higher) within user bounds; never touches thresholds.
- Files/modules: `source/feedback/{metrics,sampler,threshold}/`
- Depends on: T31, T29
- Acceptance criteria: POLICY_VIOLATION doesn't change EWMA; one ATTACK moves EWMA by α·(1−prev); N stays in bounds; thresholds unchanged after 1000 updates; state survives restart.

### [T36] [P1] [TODO] Telemetry sender
- Description: Batched, async, off the request path; redacted summaries + active version + degraded state; failure drops/buffers, never affects decisions.
- Files/modules: `source/shared/telemetry/` (proxy side)
- Depends on: T1A, T31
- Acceptance criteria: With control down, request latency and decisions are unchanged.

### [T37] [P1] [TODO] Nginx config and Tessera-down behavior
- Description: Nginx routes to the proxy; behavior per T00.2 when it is unreachable.
- Files/modules: `deploy/nginx/tessera.conf`
- Depends on: T32, T00 (point 2)
- Acceptance criteria: Configured behavior observed via curl with the proxy stopped.

### [T38] [P2] [TODO] Redis verdict cache
- Description: Cache `StaticVerdict` under `redis.tenant(tenantId)` keyed by `policyVersion + endpoint + requestHash`; Redis error → recompute; never cache JEV-dependent decisions.
- Files/modules: `source/core/static-analysis/verdict-cache.ts`
- Depends on: T31, T24 (collision-free hash)
- Acceptance criteria: Same request hits; different tenant/version misses; Redis down → same results.

### 4. Collector and policy pipeline

### [T40] [P1] [PARTIAL] Collector: environment analysis
- Owner: Antek
- Done: `EnvironmentAnalyzer` (nmap, nuclei, trivy, httpx, lynis), injectable `CommandRunner`, timeouts, partial-failure results, parser + analyzer tests, mock script.
- Description:
  - Add Syft for the SBOM (dependency names/versions) — trivy covers CVEs but not the dependency inventory the analysis needs.
  - Zod schema for `EnvironmentAnalysisResult` in the shared upload contract (T04).
  - Gate active scanners (nuclei, nmap) per T00.9.
- Files/modules: `source/analysis/environment/`, `source/analysis/dependencies/`
- Depends on: T04, T00 (point 9)
- Acceptance criteria: Fixture project yields dependencies from Syft; result validates against the shared schema; active scanners do not run unless enabled.

### [T41] [P1] [TODO] Collector CLI: source, redaction, upload
- Owner: Antek
- Description:
  - `collector.ts`: accept `gitUrl + commit` or a local path; check out the exact revision; record `sourceRevision`.
  - Redact secret values in `.env`/JSON/YAML while preserving structure, before anything leaves the process.
  - Build one context package (source files needed, environment result, `sourceRevision`) and upload to T16 with `COLLECTOR_KEY`. Print what is uploaded.
- Files/modules: `source/collector.ts`, `source/analysis/git/`, `source/analysis/redaction/` (new)
- Depends on: T40, T16
- Acceptance criteria: Checked-out HEAD = requested commit; `DB_PASSWORD=x` → `DB_PASSWORD=<redacted>` in the package; upload with the wrong tenant gets 403.

### [T42] [P2] [TODO] Provider-independent AI client
- Owner: Antek
- Description: `AiModel` port `generateStructured<T>(prompt, zodSchema) → T` with one adapter; schema-invalid output is a typed error. Control-plane only.
- Files/modules: `source/control/ai/` (new)
- Depends on: T03
- Acceptance criteria: Invalid output → typed error; valid output typed.

### [T43] [P2] [TODO] AI application analysis → `AnalysisCompleted`
- Owner: Antek
- Description: On `AnalysisContextReceived`, produce `{sourceRevision, analysisVersion, apiSurface, dependencies, environment, configuration, cves, findings}` (findings keep source/evidence); store in `tenantDb`; emit `AnalysisCompleted`/`AnalysisFailed`.
- Files/modules: `source/analysis/surface/` (control side), `source/analysis/index.ts`
- Depends on: T16, T17, T42
- Acceptance criteria: With a fake AI adapter, output validates, is stored and the event is emitted once; failure → `AnalysisFailed`, active policy unchanged.

### [T44] [P2] [TODO] Policy generation from analysis
- Owner: Antek
- Description: On `AnalysisCompleted`, generate human-readable + structured policy (schema-validated), store as non-active version, emit `PolicyGenerated`/`PolicyGenerationFailed`; idempotent per `analysisVersion`.
- Files/modules: `source/control/policy-generation/`
- Depends on: T43, T18
- Acceptance criteria: Duplicate event → one version; invalid AI output → `PolicyGenerationFailed`; active unchanged.

### [T45] [P2] [TODO] Natural-language policy edit
- Owner: Antek
- Description: Admin endpoint for an edited NL policy; the policy-generation LLM (not JEV) reinterprets it; compiled and sent to approval; response states that reinterpretation may lose precision.
- Files/modules: `source/control/policy-generation/`, `source/control/policy-api/`
- Depends on: T44, T19
- Acceptance criteria: Response includes the precision notice; edit creates a pending version; active unchanged.

### [T46] [P3] [TODO] Incremental analysis from Git diff
- Description: Previous analysis + `git diff`; recompute only affected endpoints, dependencies and config.
- Files/modules: `source/analysis/`
- Depends on: T43
- Acceptance criteria: A diff touching one route file changes only that endpoint's entries.

### [T47] [P3] [TODO] Cleanup
- Description: Remove `source/shared/logger/done.txt`, empty files and `.gitkeep`s in folders with code; update `package.json` metadata (`name: backend`, `main: index.js`, repository URL).
- Files/modules: as listed
- Depends on: —
- Acceptance criteria: `git ls-files` lists no placeholder files in folders with code.

---

## Recommended Next Steps

1. **Unblock everyone (today):** T01 (fix `upstream.ts`, scripts, alias) → T02 (split entry points, import rules) → T04 (contracts incl. tool catalog and `ActiveBundle`). These define the shapes both tracks code against.
2. **Dawid — static analysis:** T26 (order-independent aggregator; needs T00.7) → T25 (registry + plan from policy, missing-field handling) → T27 → T28.
3. **Antek — collector & policy pipeline:** finish T40 (Syft, Zod schema) → T41 collector CLI. Once T16 exists, upload end-to-end; then T42 → T43 → T44.
4. **Control-plane core + distribution (unassigned, critical path for P0):** T10 → T11 → T12 → T13 → T14 → T15.
5. **Proxy runtime (unassigned):** T20 → T21/T22 → T23/T24 → T29 → T31 → T32.

**Needs owner input now:** T00.1 (JEV API) blocks T30 and therefore T31/T32. T00.4 blocks T20, T00.7 blocks T26, T00.8 blocks T13, T00.9 gates T40.
