# Tessera TODO

Last synced with codebase: 2026-10-03 (HEAD `0f0277c` + uncommitted storage/config work)

## Current Status

The repository is a single flat project (`source/` at the root, no nested `backend/` repo). Scaffolding, configuration loading, storage and the message broker exist. No part of the request path (tenant resolution, policy, normalization, static analysis, sampling, JEV, decision, forwarding) works yet.

Done:
- **Tooling:** `package.json` (only a `dev` script: nodemon + tsx), strict `tsconfig.json` with the `@tessera/*` path alias, ESLint, Prettier, and `vitest.config.ts` (it includes `tests/**/*.test.ts`, but `tests/` does not exist and `npm test` is a placeholder).
- **Module layout:** `source/{edge,core,control,feedback,analysis,shared}/*` with one folder per module. Most `index.ts` files are empty.
- **Config** ([source/shared/config/index.ts](source/shared/config/index.ts)): `.env` loading plus `requireEnv`, `redisUrl`, `mongoUrl`, `mongoDbName`. `.env.example` exists.
- **Storage** ([source/shared/storage/](source/shared/storage/)):
  - `MongoStorage` uses one database per tenant (`tenantDb(tenantId)` → `{dbName}_t_{tenantId}`), a platform DB (`db`), and `listTenantIds()`.
  - `RedisStorage` + `TenantRedis` prefix every key with `tessera:{tenantId}:`. `pushRecent`/`recent` already provide the "last N per key" history primitive.
  - `MongoRepository<T>` provides generic collection access.
  - `assertTenantId` validates tenant ids (`A-Za-z0-9_-`, max 40).
- **Broker** ([source/shared/broker/connect.ts](source/shared/broker/connect.ts)): Redis pub/sub `Broker` with `publish`, `subscribe` and `psubscribe`. Handlers are guarded against throws.
- **Bootstrap** ([source/bootstrap.ts](source/bootstrap.ts)): Mongo is required, and Redis and the broker are optional (5 s timeout). It starts ingress and shuts down gracefully on SIGINT/SIGTERM.
- **Ingress** ([source/edge/ingress/server.ts](source/edge/ingress/server.ts)): a Fastify server that listens but has no routes.
- **Contracts** ([source/shared/contracts/](source/shared/contracts/)): `Endpoint`, `NormalizedRequest`, `RequestField` and `RequestFile` exist as TS interfaces only.
- **Static analysis:** [Tool.ts](source/core/static-analysis/shared/Tool.ts) has the abstract `Tool<C>` with context types `field | file | full`, `ToolResult` (with `verdict`) and `ToolCategory`. There is one tool, [stringLength.ts](source/core/static-analysis/tools/schema/stringLength.ts).
- **Spec decisions now settled in the references:**
  - A tool error yields `ERROR`, which goes to the configured failure behavior.
  - `ToolResult` has `verdict`.
  - Score over the threshold with confidence under the threshold → `ALLOW`.
  - Attack rate is tracked per tenant and per endpoint.
  - A natural-language policy edit is reinterpreted by the policy-generation LLM, not JEV.
  - Tenant isolation is by database or namespace (`operations.md`).

Known defects in existing code:
- `edge/ingress/server.ts` loads env a second time via `@fastify/env` (reading `source/.env`, not `.env`) and creates a **second** `Broker`, separate from the one in bootstrap.
- `stringLength.ts` hard-codes its config (`10`) and its comparison operator.
- `stringLength.ts` imports `@tessera/shared/contracts/Request`, but the vitest alias maps every `@tessera/x` to `source/x/index.ts`, so that deep import breaks under tests.
- `NormalizedRequest.timestamp` is a `number`, while `contracts.md` says `string`.
- `source/shared/storage/repositories/getDatabasesFromMongo.ts` is an empty file.
- `source/shared/logger/done.txt` is a stray file.
- `eslint`, `typescript-eslint`, `@eslint/js` and `vitest` are listed in `dependencies` instead of `devDependencies`.

Conventions used in this list:
- Paths are real `source/...` paths. Each module exposes its public API through `index.ts`.
- HTTP server: **Fastify**. The architecture skill says Express; see T00.
- The proxy (tenant traffic) and the admin API run on **separate ports**, so admin routes can never collide with protected-application paths.
- Tenant data is stored only through `mongo.tenantDb(tenantId)` and `redis.tenant(tenantId)`. The platform DB (`mongo.db`) holds only the tenant registry.
- Tenants and policies enter the system **only through the admin API**. There is no seed script.

**Milestone P0 — runtime slice:** a tenant and policy are created through the admin API, and a request is proxied end-to-end (normalize → static analysis → sampling → JEV → decision → forward or 403).

---

## TODO

### [T00] [P0] [TODO] Remaining open decisions
- Description: These must be decided by the project owner (not invented) and recorded in the relevant reference files:
  1. **JEV API:** endpoint, auth, and the request/response wire format. The owner will provide these; they block T15.
  2. **Tessera-down behavior:** does Nginx fail open (route straight to the upstream) or fail closed (503)? Is it set per tenant? 
  3. **Unknown endpoint:** pass-through is the stated default. Confirm it, and name the per-tenant config key.
  4. **Startup with an invalid active policy:** should Tessera refuse to start, or skip that tenant and apply its failure behavior?
  5. **HTTP stack:** update the skill text (`SKILL.md`, `system.md`) from Express to Fastify.
  6. **`NormalizedRequest.timestamp`:** `number` (code) or ISO `string` (contracts)?
- Files/modules: `.claude/skills/project architectuer/SKILL.md`, `.claude/skills/project architectuer/references/{system,runtime,contracts,operations}.md`
- Depends on: —
- Acceptance criteria: Each point has a written answer in the references, and no two reference files contradict each other.

### [T01] [P0] [PARTIAL] Tooling: build, lint, test
- Done: tsconfig, eslint, prettier, vitest config, `dev` script.
- Description:
  - Add the `build` (`tsc --noEmit` or emit to `dist`), `lint` and `test` (`vitest run`) scripts.
  - Create `tests/` with one smoke test.
  - Fix the vitest alias so deep imports (`@tessera/a/b/File`) resolve to the file when one exists, falling back to `index.ts`. Alternatively, ban deep imports via ESLint and import only through module `index.ts`.
  - Add `zod`.
  - Move the lint and test packages to `devDependencies`.
- Files/modules: `package.json`, `vitest.config.ts`, `eslint.config.ts`, `tests/`
- Depends on: —
- Acceptance criteria: `npm run build`, `npm run lint` and `npm test` exit 0. A test that imports `StringLength` runs.

### [T02] [P0] [PARTIAL] Typed configuration and local dependencies
- Done: `.env` loading, `REDIS_URL`/`MONGO_URL`/`MONGO_DB_NAME`, `.env.example`.
- Description:
  - Add validated config for `PROXY_PORT`, `ADMIN_PORT`, `ADMIN_API_KEY`, `JEV_URL`, `JEV_API_KEY`, `JEV_TIMEOUT_MS`, `LOG_DIR`, `MAX_BODY_BYTES` and `TRUSTED_PROXIES`.
  - Validate all required config at startup, before connecting.
  - Remove `@fastify/env` and the second `Broker` from the ingress. The ingress receives its config (and anything else it needs) from bootstrap.
  - Add `docker-compose.yml` with MongoDB, Redis and a tiny sample upstream app for tests.
  - Never read secrets from Mongo.
- Files/modules: `source/shared/config/index.ts`, `source/edge/ingress/server.ts`, `source/bootstrap.ts`, `docker-compose.yml`, `.env.example`
- Depends on: T01
- Acceptance criteria:
  - Starting with a missing required variable exits non-zero with a message naming the variable.
  - `docker compose up` starts all three services, and Tessera connects to Mongo and Redis.
  - Only one `Broker` instance exists at runtime.

### [T03] [P0] [PARTIAL] Contracts as Zod schemas
- Done: TS interfaces for `NormalizedRequest`, `RequestField`, `RequestFile`, `Endpoint` and `ToolResult`.
- Description:
  - Implement the `contracts.md` types as Zod schemas with inferred TS types: `NormalizedRequest`, `RequestField`, `RequestFile`, `ToolResult`, `StaticVerdict`, `JevInput`, `JevResult`, `Decision`, `SamplingConfig`, `AdaptiveState`, `Policy`, `EndpointPolicy`, `FieldPolicy`, `ToolConfig`.
  - Request contracts stay in `shared/contracts`, since edge and core both use them. Every other type is owned and exported by its module.
  - Move `ToolResult` out of `Tool.ts` into the static-analysis contracts.
- Files/modules: `source/shared/contracts/`, `source/core/{static-analysis,jev,decision,policy,sampling}/contracts.ts`, `source/feedback/metrics/contracts.ts`
- Depends on: T01, T00 (point 6)
- Acceptance criteria:
  - Unit tests reject a `JevResult` with `score: 7`, a missing `confidence` or an unknown `verdict`.
  - Unit tests reject a `Policy` without `tenantId` or `version`.
  - Valid fixtures parse.

### [T04] [P0] [TODO] Tenancy: tenant registry and resolution
- Description:
  - Store a `tenants` collection in the platform DB (`mongo.db`) holding `tenantId`, routing (`host`/IP + `pathPrefix`), `upstreamUrl`, failure behavior (`staticAnalysisError`, `jevUnavailable`, `suspiciousWhenJevUnavailable`), JEV thresholds with `locked` flags, and `unknownEndpointBehavior`.
  - Add a resolver that maps (host, path) to a tenant using longest-prefix match.
  - Load tenants into memory at startup.
  - The tenant's own database is created on first write via `tenantDb`.
- Files/modules: `source/core/tenancy/`
- Depends on: T02, T03
- Acceptance criteria:
  - Two tenants on the same host with prefixes `/a` and `/a/b` resolve correctly.
  - An unmatched host returns "no tenant".
  - A missing failure-behavior field fails validation (no implicit default).
  - An invalid `tenantId` is rejected by `assertTenantId`.

### [T05] [P0] [TODO] Policy store and runtime snapshot
- Description:
  - Policy versions live in `tenantDb(tenantId)`: human-readable text, structured policy, and compiled toolchain, with a content hash as `version`. Versions are insert-only.
  - Each tenant has an active-version pointer, and activation updates it in one atomic write.
  - On startup, load every tenant's active policy into a frozen in-memory snapshot and build the endpoint matcher (T07).
  - Each request takes one snapshot reference for its whole lifetime.
  - An invalid stored policy is handled as decided in T00 point 4.
- Files/modules: `source/core/policy/`
- Depends on: T03, T04
- Acceptance criteria:
  - Re-inserting identical content yields the same `version`.
  - Updating an existing version is rejected.
  - Tenant A cannot read or activate tenant B's version.
  - The snapshot is frozen (mutation throws).
  - A request reads exactly one `policyVersion`.

### [T06] [P0] [TODO] Admin API: auth, tenant upsert, policy import, activation
- Description:
  - A separate Fastify server on `ADMIN_PORT`, with bearer auth from `ADMIN_API_KEY` on every route.
  - Endpoints: create/update tenant config, import a structured policy (validate → store version, no activation), and activate a version.
  - Controllers stay thin and call the public APIs of tenancy and policy.
  - Started from `bootstrap.ts`.
- Files/modules: `source/control/policy-api/`, `source/bootstrap.ts`
- Depends on: T04, T05
- Acceptance criteria:
  - Requests without a valid key get 401 on every route.
  - Importing an invalid policy returns 400 and stores nothing.
  - Importing a valid policy returns its `version`.
  - Admin routes are not reachable on the proxy port.

### [T07] [P0] [TODO] Endpoint matcher
- Description:
  - Match `method + path` against the policy's endpoint templates (e.g. `/users/:id`), preferring exact matches over parameterized ones.
  - Return the matched `EndpointPolicy` and the path params.
  - An unmatched request returns "unknown endpoint".
- Files/modules: `source/core/policy/endpoint-matcher.ts`
- Depends on: T03
- Acceptance criteria: Tests cover exact vs. parameterized precedence, method mismatch → unknown, and trailing-slash behavior (documented and tested).

### [T08] [P0] [TODO] Ingress raw body and unchanged upstream forwarding
- Description:
  - Add a Fastify catch-all route (any method and path) with a raw `Buffer` content-type parser for every content type and a `MAX_BODY_BYTES` limit. The original bytes are kept.
  - After an ALLOW, forward method, path, query, headers and body unchanged to the tenant's `upstreamUrl` using undici.
  - Stream the upstream response back unchanged.
  - An upstream error or timeout returns 502/504 and does not replace the application's behavior.
- Files/modules: `source/edge/ingress/`, `source/edge/upstream/`
- Depends on: T02, T04
- Acceptance criteria:
  - An integration test against the sample upstream shows a byte-identical body (JSON, urlencoded, multipart, binary), and an identical query string and headers apart from hop-by-hop headers.
  - Upstream status, body and headers reach the client unchanged.
  - Upstream down → 502.

### [T09] [P0] [TODO] Normalizer
- Description:
  - Build a `NormalizedRequest` from the buffered raw request: query, relevant headers, a parsed body for JSON, urlencoded and multipart, and flattened `fields` with `location` (`query|body|path|header`).
  - For each file, record `field`, `filename`, `contentType`, `size` and `magicBytes` (first N bytes, hex).
  - Take the client IP from `X-Forwarded-For`/`X-Real-IP` only when the request comes from `TRUSTED_PROXIES`.
  - Never mutate the original buffer.
  - An unparseable body produces a normalization error (handled in T16), not a silently empty body.
- Files/modules: `source/edge/normalizer/`
- Depends on: T03, T08
- Acceptance criteria:
  - Nested JSON is flattened to dotted field names with types.
  - Multipart file metadata has the correct magic bytes for PNG and PDF.
  - A spoofed `X-Forwarded-For` from an untrusted source is ignored.
  - Malformed JSON → error result.

### [T10] [P0] [PARTIAL] Tool interface, registry and Runner
- Done: abstract `Tool<C>`, context types `field | file | full`, `ToolCategory`.
- Description:
  - Extend the `Tool` interface with a typed per-tool config (from the policy's `ToolConfig`) and declared dependencies.
  - Add a registry of known tool ids.
  - The Runner builds a DAG from the endpoint's `requestTools` and `fields[].tools`, runs independent tools concurrently, and gives each tool only its declared context.
  - A thrown error or timeout becomes `status: ERROR, verdict: ERROR`, never SAFE.
  - An unknown tool id in a policy → `ERROR`.
- Files/modules: `source/core/static-analysis/shared/`, `source/core/static-analysis/runner/`, `source/core/static-analysis/tools/index.ts`
- Depends on: T03
- Acceptance criteria:
  - A dependent tool runs after its prerequisite and receives its result.
  - Independent tools overlap in time.
  - A throwing tool yields an ERROR result.
  - A field tool receives only its field.
  - A dependency cycle is rejected.

### [T11] [P0] [TODO] Aggregator
- Description: Combine `ToolResult[]` into a `StaticVerdict` using the priority `ERROR > POLICY_VIOLATION > SUSPICIOUS > SAFE`, plus compact evidence for JEV (non-SAFE findings only).
- Files/modules: `source/core/static-analysis/aggregator/`
- Depends on: T10
- Acceptance criteria:
  - Table-driven tests cover every priority combination.
  - All-SAFE → SAFE.
  - Evidence excludes SAFE results' raw output.

### [T12] [P0] [PARTIAL] Schema and resource tools
- Done: `stringLength` (hard-coded config).
- Description:
  - Rewrite `stringLength` to be config-driven (`min`/`max`).
  - Add per-field schema tools: type, required, numeric range, regex/format, enum.
  - Add per-request resource tools: body size, field count, nesting depth, array length.
- Files/modules: `source/core/static-analysis/tools/schema/`, `source/core/static-analysis/tools/resource/`
- Depends on: T10
- Acceptance criteria:
  - Wrong type → POLICY_VIOLATION.
  - Missing required field → POLICY_VIOLATION.
  - Valid value → SAFE.
  - Body over the limit → POLICY_VIOLATION.
  - No hard-coded thresholds remain.

### [T13] [P0] [TODO] Injection, URL and file-magic tools
- Description:
  - **Injection:** pattern sets for SQLi, XSS, command injection, path traversal and template injection, with a configurable action per pattern (SUSPICIOUS or POLICY_VIOLATION).
  - **URL:** allowed schemes; block private, loopback, link-local and metadata IPs, checked on a literal parse without DNS resolution.
  - **File-magic:** compare the declared content type with the magic bytes, and check against the allowed types.
- Files/modules: `source/core/static-analysis/tools/{injection,url}/`, `source/core/static-analysis/tools/file/` (new)
- Depends on: T10
- Acceptance criteria:
  - `' OR 1=1 --`, `<script>` and `../../etc/passwd` are flagged.
  - `http://169.254.169.254/` is flagged.
  - A `.png` upload with PDF magic bytes → POLICY_VIOLATION.
  - Benign values → SAFE.

### [T14] [P0] [TODO] Sampling with secure randomness
- Description:
  - `shouldSample(samplingConfig) → boolean` uses `crypto.randomInt` and clamps N to `[minN, maxN]`.
  - Only SAFE requests consult sampling. SUSPICIOUS requests always go to JEV.
- Files/modules: `source/core/sampling/`
- Depends on: T03
- Acceptance criteria:
  - N=0 never samples.
  - N=100 always samples.
  - N=10 samples 10% ± 1% over 100k trials.
  - `Math.random` is not used.

### [T15] [P0] [BLOCKED on T00.1] JEV client
- Description:
  - A JEV port `classify(JevInput) → JevResult` with an HTTP adapter: timeout, API key from env, Zod-validated response.
  - An invalid or late response counts as JEV unavailable, not as a verdict.
  - A deterministic stub adapter for tests only.
  - `JevInput` carries only the context the policy requires.
  - Implement once the owner provides the JEV API (T00 point 1).
- Files/modules: `source/core/jev/`
- Depends on: T03, T00 (point 1)
- Acceptance criteria:
  - Malformed response → `JevUnavailable`.
  - Timeout → `JevUnavailable`.
  - A valid response parses.
  - The adapter is selected by config.

### [T16] [P0] [TODO] Decision orchestrator
- Description:
  - Wire `tenant → snapshot → endpoint → normalize → static analysis → sampling → JEV → thresholds → Decision`.
  - Apply the tenant's failure behavior for normalization errors, static `ERROR` and JEV unavailable.
  - ATTACK only when `score > maliciousScoreThreshold && confidence > confidenceThreshold`; otherwise ALLOW.
  - An unknown endpoint follows the per-tenant config.
  - No Fastify types in this module.
- Files/modules: `source/core/decision/`
- Depends on: T05, T07, T09, T11, T14, T15, T00 (point 3)
- Acceptance criteria:
  - A table-driven test asserts the final ALLOW/BLOCK for:
    - POLICY_VIOLATION (JEV never called)
    - ERROR
    - SUSPICIOUS + ATTACK
    - SUSPICIOUS + BENIGN
    - SAFE unsampled (JEV never called)
    - SAFE sampled + ATTACK
    - JEV unavailable under each failure setting
    - low confidence
  - Every `Decision` carries `policyVersion`.
  - Tenant B's policy is never applied to tenant A's request.

### [T17] [P0] [TODO] End-to-end proxy integration
- Description:
  - Connect ingress → decision orchestrator → upstream forward or BLOCK response.
  - A blocked request returns a fixed 403 body containing `requestId` (no internal evidence leaked) and is never sent upstream.
- Files/modules: `source/edge/ingress/`, `source/bootstrap.ts`, `tests/e2e/`
- Depends on: T06, T08, T16
- Acceptance criteria: Using the docker-compose services, a tenant and policy created through the admin API, and the JEV stub:
  - A benign request reaches the sample upstream and returns its response.
  - A SQLi request gets 403, and the upstream receives nothing.
  - Two tenants with different policies are enforced independently.

### [T18] [P1] [TODO] Structured decision logging
- Description:
  - JSON logs to files under `LOG_DIR` via pino.
  - Each decision logs tenant, endpoint, policyVersion, static verdict, sampled, JEV verdict/score/confidence, thresholds, action, failure state and requestId.
  - Field values, bodies, auth headers and cookies are redacted.
  - Replace the `console.*` calls in bootstrap, storage and broker.
- Files/modules: `source/shared/logger/`, `source/core/decision/`
- Depends on: T16
- Acceptance criteria:
  - A decision log line parses as JSON and contains all the listed keys.
  - `Authorization`, `Cookie` and body values never appear in the output.

### [T19] [P1] [PARTIAL] Request history (last 3 per tenant + client IP)
- Done: `TenantRedis.pushRecent`/`recent` (LPUSH + LTRIM + EXPIRE under the tenant prefix).
- Description:
  - After each decision, push a compact request summary to `redis.tenant(tenantId)` under key `hist:{clientIp}` (max 3, with TTL).
  - Read it into `JevInput.recentRequests`.
  - On a Redis error, continue with empty history and log the error.
- Files/modules: `source/core/history/`
- Depends on: T16
- Acceptance criteria:
  - After 5 requests, only the last 3 are returned.
  - Tenant A + IP X never sees the history of tenant B + IP X.
  - With Redis stopped, requests still get correct decisions.

### [T20] [P1] [TODO] Adaptive state persistence and EWMA update
- Description:
  - Persist `AdaptiveState` per tenant (tenant EWMA, per-endpoint EWMA, global α) in `tenantDb`, and load it at startup.
  - Update it only from JEV ATTACK/BENIGN results, never from static blocks or unsampled requests.
  - Update in memory on the request path, and flush periodically and on shutdown.
- Files/modules: `source/feedback/metrics/`
- Depends on: T16
- Acceptance criteria:
  - A POLICY_VIOLATION does not change EWMA.
  - One ATTACK moves EWMA by exactly α·(1−prev).
  - State survives a restart.

### [T21] [P1] [TODO] Adaptive sampling controller
- Description:
  - Compute the endpoint's `probabilityN` from the endpoint and tenant EWMA (endpoint weighted higher, weights configurable), clamped to `[minN, maxN]`.
  - The controller never touches thresholds.
  - Sampling (T14) reads the current N from the controller.
- Files/modules: `source/feedback/sampler/`, `source/feedback/threshold/` (read-only threshold guard)
- Depends on: T20, T14
- Acceptance criteria:
  - N stays within bounds for EWMA 0 and 1.
  - A higher endpoint EWMA gives a higher N than the same tenant EWMA.
  - Thresholds are unchanged after 1000 updates.

### [T22] [P1] [PARTIAL] Events: envelope, outbox and inbox on the Broker
- Done: Redis pub/sub `Broker` ([source/shared/broker/](source/shared/broker/)).
- Description:
  - A versioned envelope `{eventId, eventType, version, tenantId, aggregateId, occurredAt, payload}`.
  - A Mongo outbox, written in the same local transaction as the state change. A relay publishes it through `Broker`.
  - Pub/sub is at-most-once, so the outbox is the source of truth, and the relay re-publishes entries that have no inbox record after a timeout.
  - A Mongo inbox (`consumer + eventId` unique) makes handlers idempotent.
  - A failed handler retries, then emits an explicit failure event.
- Files/modules: `source/control/events/`
- Depends on: T02
- Acceptance criteria:
  - A duplicate delivery runs the side effect once.
  - A crash between commit and publish still publishes after restart.
  - An event without `tenantId` is rejected.

### [T23] [P1] [TODO] Policy compiler and toolchain generator
- Description:
  - Compile a structured policy into a toolchain using only registered tools and validated configs.
  - Infer default tools per field type.
  - Saga step: `PolicyGenerated|PolicyImported → PolicyCompiled | PolicyCompilationFailed`.
  - On failure, the active policy is unchanged.
- Files/modules: `source/control/policy-compiler/`, `source/control/toolchain-generator/`
- Depends on: T05, T10, T22
- Acceptance criteria:
  - An unknown tool → `PolicyCompilationFailed`, and the active policy is unchanged.
  - A string field with maxLength gets a schema tool.
  - A duplicate event produces one compiled version.

### [T24] [P1] [TODO] Approval and activation saga steps
- Description:
  - Admin approve/reject → `PolicyApproved`/`PolicyRejected`.
  - Activation sets the active pointer for a compiled version and emits `PolicyActivated`.
  - The running snapshot is not hot-swapped; the new version takes effect on restart.
  - Approval can be configured as required for generated and/or edited policies.
- Files/modules: `source/core/policy/`, `source/control/policy-api/`
- Depends on: T23, T06
- Acceptance criteria:
  - An uncompiled or failed version cannot be activated.
  - A running process keeps its old version until restart.
  - A duplicate `PolicyApproved` is a no-op.

### [T25] [P1] [TODO] Nginx config and Tessera-down behavior
- Description: Nginx config that routes to Tessera, with the behavior decided in T00 point 2 when Tessera is unreachable.
- Files/modules: `deploy/nginx/tessera.conf`
- Depends on: T17, T00 (point 2)
- Acceptance criteria:
  - With Tessera stopped, the configured behavior is observed via curl.
  - With Tessera running, all traffic goes through it.

### [T26] [P2] [TODO] Provider-independent AI client with structured output
- Description:
  - An `AiModel` port: `generateStructured<T>(prompt, zodSchema) → T`, with one adapter.
  - Output that fails the schema is an error.
  - Keys come from env.
- Files/modules: `source/shared/ai/` (new; used by analysis and policy generation)
- Depends on: T02
- Acceptance criteria:
  - Schema-invalid output → typed error.
  - Valid output is returned typed.

### [T27] [P2] [TODO] Application analysis: source acquisition and secret redaction
- Description:
  - Accept `gitUrl + commit` or a local path, check out the exact revision, and record `sourceRevision`.
  - Redact secret values in `.env`/JSON/YAML before anything leaves the process.
- Files/modules: `source/analysis/git/`
- Depends on: T02
- Acceptance criteria:
  - Checked-out HEAD = requested commit.
  - `DB_PASSWORD=x` → `DB_PASSWORD=<redacted>` in the AI payload.

### [T28] [P2] [TODO] Application analysis: dependencies, CVEs, environment
- Description:
  - Syft (SBOM) and Trivy (CVEs), parsed into structured, source-attributed results.
  - A tool failure is recorded as a partial result.
  - Nmap is out of scope.
- Files/modules: `source/analysis/{dependencies,cve,environment}/`
- Depends on: T27
- Acceptance criteria:
  - A fixture project yields dependency names/versions and CVE ids tagged with the tool name.
  - A missing Trivy binary → recorded error, and analysis continues.

### [T29] [P2] [TODO] Application analysis: API surface and AI analysis → `AnalysisCompleted`
- Description:
  - Produce a versioned model: `{sourceRevision, analysisVersion, apiSurface, dependencies, environment, configuration, cves, findings}`.
  - Store it in `tenantDb`.
  - Emit `AnalysisCompleted`/`AnalysisFailed` via the outbox.
- Files/modules: `source/analysis/surface/`, `source/analysis/index.ts`
- Depends on: T26, T27, T28, T22
- Acceptance criteria:
  - With a fake AI adapter, the output validates and is stored, and the event is emitted once.
  - On failure, `AnalysisFailed` is emitted and the active policy is unchanged.

### [T30] [P2] [TODO] Policy generation from analysis
- Description:
  - Handle `AnalysisCompleted`: generate a human-readable and a structured policy, schema-validated.
  - Store it as a non-active version.
  - Emit `PolicyGenerated`/`PolicyGenerationFailed`.
  - Idempotent per `analysisVersion`.
- Files/modules: `source/control/policy-generation/`
- Depends on: T29, T23
- Acceptance criteria:
  - A duplicate event produces one version.
  - Invalid AI output → `PolicyGenerationFailed`.
  - The active policy is unchanged in both cases.

### [T31] [P2] [TODO] Natural-language policy edit
- Description:
  - An admin endpoint accepts an edited natural-language policy.
  - The policy-generation LLM reinterprets it into a structured policy, which is compiled and enters approval.
  - The response states that reinterpretation may lose precision.
- Files/modules: `source/control/policy-generation/`, `source/control/policy-api/`
- Depends on: T30, T24
- Acceptance criteria:
  - The response includes the precision notice.
  - The edit creates a pending version, and the active one is unchanged.

### [T32] [P2] [TODO] Redis verdict cache
- Description:
  - Cache `StaticVerdict` via `redis.tenant(tenantId)`, keyed by `policyVersion + method + path + hash(query, relevant headers, body)`.
  - On a Redis error, recompute.
  - Never cache JEV-dependent decisions.
- Files/modules: `source/core/static-analysis/verdict-cache.ts`
- Depends on: T16
- Acceptance criteria:
  - An identical request for the same tenant hits the cache.
  - A different tenant or policyVersion misses.
  - With Redis down, results equal the uncached results.

### [T33] [P3] [TODO] Incremental analysis from Git diff
- Description: Reuse the previous analysis plus `git diff`, and recompute only the affected endpoints, dependencies and config.
- Files/modules: `source/analysis/`
- Depends on: T29
- Acceptance criteria: A fixture diff touching one route file changes only that endpoint's entries.

### [T34] [P3] [TODO] Cleanup
- Description:
  - Remove `source/shared/storage/repositories/getDatabasesFromMongo.ts` (empty) and `source/shared/logger/done.txt`.
  - Remove the `.gitkeep` files from folders that now have code.
  - Update the stale `package.json` metadata (`name: backend`, `main: index.js`, repository URL) if desired.
- Files/modules: as listed
- Depends on: —
- Acceptance criteria: `git ls-files` lists no empty or placeholder files in folders that contain code.

---

## Recommended Next Task

**[T01] Tooling, then [T02] config.** Both are small and unblock everything else. They make tests runnable and fix the duplicate env loading and the second Broker in the ingress. Then do T03 → T04/T05 → T06 → T07–T14 → T16 → T17.

**Needs owner input now:** the JEV API (T00 point 1) blocks T15 and therefore the full T16/T17 slice. T00 points 3 and 4 are needed before T16 and T05.


// Antek normalizer request  environment analisis, policy pipline, 
// Dawid static analisis pipline, aggregator i runner
