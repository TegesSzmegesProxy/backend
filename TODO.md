# Tessera TODO

Last synced with codebase: 2026-10-03 (parent `10e1ef3`, backend `9e8e254`)

## Current Status

No implementation exists yet. The repository contains:

- `.gitignore` (Node/macOS)
- `backend/`: a nested Git repo (`TegesSzmegesProxy/backend`) containing only `README.md`. The parent repo tracks it as a gitlink but has no `.gitmodules`, so a fresh clone of the parent gets an empty, unfetchable `backend/`.
- `.claude/skills/*`: architecture specification (system, runtime, static analysis, policy, analysis, adaptation, operations, contracts) and development rules (modular monolith, choreographed sagas over NATS JetStream with inbox/outbox, strict TypeScript, tenant isolation).

Everything below is new work. It is ordered so that the runtime enforcement path (the proxy) works end-to-end first, using a manually imported structured policy and a stubbed JEV. The control-plane saga (analysis → generation → compilation → approval → activation) follows.

Conventions used in this list:
- Module paths are proposals under `backend/src/modules/<module>/` (one folder per module, public API via `index.ts`).
- The proxy (tenant traffic) and admin/control API are served on **separate ports** so admin routes can never collide with protected-application paths.

---

## TODO

### [T00] [P0] [TODO] Resolve architecture-spec contradictions and open decisions
- Description: The spec has conflicts and gaps that affect request-path semantics. Each must be decided by the project owner (not invented) and recorded in the relevant reference file:
  1. **Tool error handling:** `contract.md`/`static-analysis.md` say "any tool error blocks"; `runtime.md`/SKILL say "`ERROR` → configured failure behavior". Which wins?
  2. **ToolResult shape:** `contract.md` `ToolResult` has no `verdict`; `static-analysis.md` requires `tool, status, verdict, evidence`. Add `verdict` to the contract?
  3. **Low-confidence JEV result:** if `score > maliciousScoreThreshold` but `confidence <= confidenceThreshold`, is the request ALLOWed, BLOCKed or routed to failure behavior? Also: is JEV `verdict` used at all, or only `score`/`confidence`?
  4. **Unknown endpoint default:** pass-through is the stated default; confirm, and confirm the config key (per tenant).
  5. **Attack-rate scope:** `system.md` says per tenant; `adaption.md`/`contract.md` say tenant + endpoint. Confirm tenant + endpoint.
  6. **NL policy reinterpretation:** done by JEV (`policy.md`) or by the generation LLM (SKILL)?
  7. **JEV API:** endpoint, auth and request/response wire format of the external JEV service.
  8. **Tessera-down behavior:** does Nginx fail open (route straight to upstream) or fail closed (503)? Is it per tenant?
- Files/modules: `.claude/skills/project architectuer/references/{contract,runtime,static-analysis,adaption,policy,operations}.md`
- Depends on: —
- Acceptance criteria: Each of the 8 points has a written answer in the reference docs, and no two reference files contradict each other on these points.

### [T01] [P0] [TODO] Fix `backend` repository linkage
- Description: Either add a `.gitmodules` entry for `backend` → `https://github.com/TegesSzmegesProxy/backend`, or remove the gitlink and vendor the backend into the parent repo. Choose one model.
- Files/modules: `/.gitmodules`, `/backend`
- Depends on: —
- Acceptance criteria: `git clone --recurse-submodules <parent>` (or a plain clone if vendored) produces a populated `backend/` containing `README.md`.

### [T02] [P0] [TODO] Scaffold backend TypeScript/Express project
- Description: Create `package.json`, a strict `tsconfig.json` (`strict`, `noUncheckedIndexedAccess`), ESLint, a test runner (Vitest) and scripts `build`, `test`, `lint`, `dev`. Create the module folder layout (`edge`, `normalizer`, `tenancy`, `policy`, `static-analysis`, `sampling`, `jev`, `history`, `decision`, `adaptive`, `events`, `analysis`, `policy-generation`, `policy-compiler`, `admin-api`) plus minimal `src/shared` for generic code only. Add a `main.ts` that starts the proxy server and the admin server on two configured ports.
- Files/modules: `backend/package.json`, `backend/tsconfig.json`, `backend/src/main.ts`, `backend/src/modules/*/index.ts`
- Depends on: T01
- Acceptance criteria: `npm run build`, `npm run lint` and `npm test` (with one placeholder test) exit 0, and `npm run dev` starts both servers on their configured ports.

### [T03] [P0] [TODO] Environment configuration and local dependencies
- Description: Validate typed config from env vars at startup (ports, Mongo URI, Redis URL, NATS URL, JEV URL/key, AI key, log dir). Fail startup on invalid config. Add `docker-compose.yml` with MongoDB, Redis, NATS (JetStream enabled) and a tiny sample upstream app for tests. Never read secrets from Mongo.
- Files/modules: `backend/src/config.ts`, `backend/docker-compose.yml`, `backend/.env.example`
- Depends on: T02
- Acceptance criteria: Starting with a missing required var exits non-zero with a message naming the var. `docker compose up` brings up all 4 services, and Tessera connects to Mongo/Redis/NATS on startup.

### [T04] [P0] [TODO] Shared contracts with runtime validation
- Description: Implement the `contract.md` types (`NormalizedRequest`, `RequestField`, `RequestFile`, `ToolResult`, `StaticVerdict`, `JevInput`, `JevResult`, `Decision`, `SamplingConfig`, `AdaptiveState`, `Policy`, `EndpointPolicy`, `FieldPolicy`, `ToolConfig`) as Zod schemas with inferred TS types. Each type is owned by its module and exported through the module's public API, not a global dump.
- Files/modules: `backend/src/modules/{normalizer,static-analysis,jev,decision,policy,sampling,adaptive}/contracts.ts`
- Depends on: T02, T00 (points 2, 3)
- Acceptance criteria: Unit tests reject `JevResult` with `score: 7`, a missing `confidence` or an unknown `verdict`, and reject a `Policy` without `tenantId`/`version`. Valid fixtures parse.

### [T05] [P0] [TODO] Tenancy module: tenant config storage and resolution
- Description: Mongo `tenants` collection holding `tenantId`, routing (`host`/IP + `pathPrefix`), `upstreamUrl`, failure behavior (`staticAnalysisError`, `jevUnavailable`, `suspiciousWhenJevUnavailable`), JEV thresholds + `locked` flags, and `unknownEndpointBehavior`. Add a resolver mapping (host, path) → tenant, with longest-prefix match. Tenants are loaded into memory at startup.
- Files/modules: `backend/src/modules/tenancy/`
- Depends on: T03, T04
- Acceptance criteria: Tests show that two tenants on the same host with prefixes `/a` and `/a/b` resolve correctly, an unmatched host returns "no tenant", and a missing failure-behavior field fails validation (no implicit default).

### [T06] [P0] [TODO] Policy store: immutable versions and active pointer
- Description: Mongo collections for policy versions (human-readable text, structured policy, compiled toolchain, content hash as `version`, `tenantId`) and a per-tenant active-version pointer. Versions are insert-only. Activation updates the pointer in one atomic write.
- Files/modules: `backend/src/modules/policy/`
- Depends on: T04, T05
- Acceptance criteria: Re-inserting identical content yields the same `version`. Updating an existing version is rejected. A test shows that tenant A cannot read or activate tenant B's version.

### [T07] [P0] [TODO] Runtime policy snapshot loaded at startup
- Description: On startup, load every tenant's active policy into an in-memory immutable snapshot (and build the endpoint matcher from T10). Each request takes one snapshot reference for its whole lifetime. If any tenant's active policy fails validation, apply the configured startup behavior from T00 (do not start with partial state).
- Files/modules: `backend/src/modules/policy/runtime-snapshot.ts`
- Depends on: T06
- Acceptance criteria: Tests show that the snapshot is frozen (mutation throws), that a corrupted stored policy prevents startup or is handled per config, and that a request reads exactly one `policyVersion`.

### [T08] [P0] [TODO] Admin API authentication and structured policy import
- Description: Admin server (separate port) with API-key/bearer auth from env, applied to every route. Add endpoints: create/update tenant config, import structured policy (validate → store version, no activation), activate version. Controllers stay thin and call the tenancy/policy public APIs.
- Files/modules: `backend/src/modules/admin-api/`
- Depends on: T05, T06
- Acceptance criteria: Requests without a valid key get 401 on every route. Importing an invalid policy returns 400 and stores nothing. Importing a valid policy returns its `version`. Admin routes are not reachable on the proxy port.

### [T09] [P0] [TODO] Edge: raw ingress and unchanged forwarding
- Description: Proxy server accepts any method/path, buffers the raw body (configurable max size), and keeps the original bytes. After an ALLOW decision it forwards method, path, query, headers and body unchanged to the tenant's upstream (undici) and streams the upstream response back unchanged. Upstream errors and timeouts are returned as upstream failures, without replacing app behavior. No Express body parser on this server.
- Files/modules: `backend/src/modules/edge/`
- Depends on: T02, T05
- Acceptance criteria: Integration test against the sample upstream shows the upstream receives a byte-identical body (JSON, urlencoded, multipart, binary), identical query string and headers (except hop-by-hop headers). Upstream status/body/headers reach the client unchanged. Upstream down → 502.

### [T10] [P0] [TODO] Endpoint matcher
- Description: Match `method + path` against the policy's endpoint templates (e.g. `/users/:id`), preferring exact over parameterized matches. Return the matched `EndpointPolicy` and path params. Unmatched requests return "unknown endpoint".
- Files/modules: `backend/src/modules/policy/endpoint-matcher.ts`
- Depends on: T04
- Acceptance criteria: Tests cover exact vs param precedence, method mismatch → unknown, and trailing-slash behavior (documented and tested).

### [T11] [P0] [TODO] Normalizer
- Description: Build a `NormalizedRequest` from the buffered raw request: query, relevant headers, parsed body for JSON / urlencoded / multipart, and flattened `fields` with `location` (`query|body|path|header`). For files, record `field`, `filename`, `contentType`, `size` and `magicBytes` (first N bytes, hex). Client IP comes from a trusted `X-Forwarded-For`/`X-Real-IP` hop configured for Nginx only. Never mutate the original buffer. Unparseable bodies produce a normalization error (handled by T17), not a silent empty body.
- Files/modules: `backend/src/modules/normalizer/`
- Depends on: T04, T09
- Acceptance criteria: Tests show nested JSON flattened to dotted field names with types, multipart file metadata with correct magic bytes for PNG/PDF, a spoofed `X-Forwarded-For` from an untrusted source ignored, and malformed JSON → error result.

### [T12] [P0] [TODO] Static analysis: tool interface, registry and Runner
- Description: Define the `Tool` interface (name, declared input selector, declared dependencies, `run(input, config) → ToolResult`) and a registry of known tool types. The Runner builds a DAG from the endpoint's `requestTools` + `fields[].tools`, runs independent tools concurrently, gives each tool only its declared input, and converts thrown errors/timeouts into `status: ERROR` (never SAFE). Unknown tool type in policy → ERROR.
- Files/modules: `backend/src/modules/static-analysis/{tool.ts,registry.ts,runner.ts}`
- Depends on: T04, T00 (point 2)
- Acceptance criteria: Tests show that a dependent tool runs after its prerequisite and receives its result, independent tools overlap in time, a throwing tool yields an ERROR result, a field tool receives only its field, and a dependency cycle is rejected.

### [T13] [P0] [TODO] Static analysis: Aggregator
- Description: Combine `ToolResult[]` into a `StaticVerdict` with priority `ERROR > POLICY_VIOLATION > SUSPICIOUS > SAFE`, plus compact evidence (non-SAFE findings only) for JEV.
- Files/modules: `backend/src/modules/static-analysis/aggregator.ts`
- Depends on: T12
- Acceptance criteria: Table-driven tests cover every priority combination, all-SAFE → SAFE, and evidence that excludes SAFE results' raw output.

### [T14] [P0] [TODO] Initial tool set: schema and resource tools
- Description: `schema` tool (type, required, min/max length, numeric range, regex/format, enum) per field. `resource` tool (body size, field count, nesting depth, array length) per request.
- Files/modules: `backend/src/modules/static-analysis/tools/{schema,resource}.ts`
- Depends on: T12
- Acceptance criteria: Tests show a wrong type → POLICY_VIOLATION, a missing required field → POLICY_VIOLATION, a valid value → SAFE, and a body over the limit → POLICY_VIOLATION.

### [T15] [P0] [TODO] Initial tool set: injection, URL and file tools
- Description: `injection` tool (SQLi, XSS, command injection, path traversal, template injection pattern sets; configurable action per pattern: SUSPICIOUS or POLICY_VIOLATION). `url` tool (allowed schemes, blocks private/loopback/link-local/metadata IPs after DNS-free literal parse). `file-magic` tool (declared content type vs magic bytes, allowed types).
- Files/modules: `backend/src/modules/static-analysis/tools/{injection,url,file-magic}.ts`
- Depends on: T12
- Acceptance criteria: Tests show `' OR 1=1 --` and `<script>` flagged, `../../etc/passwd` flagged, `http://169.254.169.254/` flagged, a `.png` upload with PDF magic bytes → POLICY_VIOLATION, and benign values → SAFE.

### [T16] [P0] [TODO] JEV client with validation and dev stub
- Description: JEV port interface `classify(JevInput) → JevResult` with an HTTP adapter (timeout, API key from env, Zod-validated response; invalid or late response = JEV failure) and a deterministic stub adapter for dev/tests. Build `JevInput` with only policy-required context.
- Files/modules: `backend/src/modules/jev/`
- Depends on: T04, T00 (point 7)
- Acceptance criteria: Tests show that a malformed response → `JevUnavailable` error (not a verdict), a timeout → `JevUnavailable`, and a valid response parses. The adapter is selected by config.

### [T17] [P0] [TODO] Sampling with secure randomness
- Description: `shouldSample(endpointSamplingConfig) → boolean` using `crypto.randomInt`, clamped to `[minN, maxN]`. Only SAFE requests consult sampling. SUSPICIOUS requests always go to JEV.
- Files/modules: `backend/src/modules/sampling/`
- Depends on: T04
- Acceptance criteria: Tests show N=0 never samples, N=100 always samples, N=10 samples 10% ± 1% over 100k trials, and the implementation does not use `Math.random`.

### [T18] [P0] [TODO] Decision orchestrator (request pipeline)
- Description: Wire `tenant → snapshot → endpoint → normalize → static analysis → sampling → JEV → thresholds → Decision`. Apply tenant failure behavior for normalization error, static ERROR, and JEV unavailable (per T00). Apply thresholds `score > maliciousScoreThreshold && confidence > confidenceThreshold` → ATTACK → BLOCK. Unknown endpoint → per-tenant config. No Express types in this module.
- Files/modules: `backend/src/modules/decision/`
- Depends on: T07, T10, T11, T13, T16, T17, T00 (points 1, 3, 4)
- Acceptance criteria: A table-driven test matrix asserts the final ALLOW/BLOCK for: POLICY_VIOLATION (JEV never called), ERROR, SUSPICIOUS+ATTACK, SUSPICIOUS+BENIGN, SAFE unsampled (JEV never called), SAFE sampled+ATTACK, JEV unavailable under each failure setting, and low confidence. Every `Decision` carries `policyVersion`. A tenant-isolation test shows tenant B's policy is never applied to tenant A's request.

### [T19] [P0] [TODO] End-to-end proxy integration
- Description: Connect edge → decision orchestrator → forward/BLOCK response. A blocked request returns a fixed 403 body with `requestId` (no internal evidence leaked) and is never sent upstream.
- Files/modules: `backend/src/modules/edge/`, `backend/src/main.ts`
- Depends on: T09, T18, T08
- Acceptance criteria: An integration test using docker-compose services, an imported policy and the JEV stub shows that a benign request reaches the sample upstream and returns its response, a SQLi request gets 403 and the upstream receives nothing, and two tenants with different policies are enforced independently.

### [T20] [P1] [TODO] Structured decision logging
- Description: Use pino to write JSON logs to files. Each decision logs tenant, endpoint, policyVersion, static verdict, sampled, JEV verdict/score/confidence, thresholds, action, failure state and requestId. Field values, bodies, auth headers and cookies are redacted.
- Files/modules: `backend/src/modules/decision/decision-logger.ts`, `backend/src/shared/logger.ts`
- Depends on: T18
- Acceptance criteria: Tests show that a decision log line parses as JSON with all listed keys and that `Authorization`, `Cookie` and body values never appear in log output.

### [T21] [P1] [TODO] Redis request history (last 3 per tenant + client IP)
- Description: After each decision, push a compact request summary to `tessera:{tenantId}:hist:{clientIp}` (LPUSH + LTRIM 0 2 + TTL). Read it into `JevInput.recentRequests`. On Redis error, continue with empty history and log the error.
- Files/modules: `backend/src/modules/history/`
- Depends on: T18
- Acceptance criteria: Tests show that after 5 requests only the last 3 are returned, that tenant A + IP X never sees tenant B + IP X history, and that stopping Redis still lets requests receive correct decisions.

### [T22] [P1] [TODO] Adaptive state persistence and EWMA update
- Description: Persist `AdaptiveState` per tenant (tenant EWMA, per-endpoint EWMA, global α) in Mongo, loaded at startup. Update it from JEV ATTACK/BENIGN results only (never from static blocks or unsampled requests). Update in memory on the request path and flush to Mongo periodically and on shutdown.
- Files/modules: `backend/src/modules/adaptive/`
- Depends on: T18
- Acceptance criteria: Tests show that a POLICY_VIOLATION does not change EWMA, a single ATTACK moves EWMA by exactly α·(1−prev), and state survives a restart (flush → reload equal).

### [T23] [P1] [TODO] Adaptive sampling controller
- Description: Compute the endpoint's `probabilityN` from endpoint and tenant EWMA (endpoint weighted higher; weights configurable), clamped to `[minN, maxN]`. Never touches thresholds. Sampling (T17) reads the controller's current N.
- Files/modules: `backend/src/modules/adaptive/controller.ts`
- Depends on: T22, T17
- Acceptance criteria: Tests show that N stays within bounds for EWMA 0 and 1, that a higher endpoint EWMA gives higher N than the same tenant EWMA, and that thresholds are unchanged after 1000 updates.

### [T24] [P1] [TODO] Event infrastructure: envelope, outbox, inbox on NATS JetStream
- Description: Versioned event envelope `{eventId, eventType, version, tenantId, aggregateId, occurredAt, payload}`. A Mongo outbox is written in the same local transaction as the state change, and a relay publishes it to JetStream. A Mongo inbox (`consumer + eventId` unique) makes handlers idempotent. Failed handlers retry, then emit an explicit failure event.
- Files/modules: `backend/src/modules/events/`
- Depends on: T03
- Acceptance criteria: Tests show that delivering the same event twice runs the handler's side effect once, that a crash between commit and publish still publishes after restart (outbox relay), and that an event without `tenantId` is rejected.

### [T25] [P1] [TODO] Policy compiler (structured policy → toolchain)
- Description: Compile a structured policy into a toolchain using only registered tool types and validated configs. Infer the default tools per field type when the admin did not specify them. Run as a saga step: `PolicyGenerated|PolicyImported → PolicyCompiled | PolicyCompilationFailed`. A failure leaves the active policy unchanged.
- Files/modules: `backend/src/modules/policy-compiler/`
- Depends on: T06, T12, T24
- Acceptance criteria: Tests show that an unknown tool type → `PolicyCompilationFailed` with the active version unchanged, that a string field with maxLength gets a `schema` tool, that duplicate `PolicyGenerated` delivery produces one compiled version, and that the output validates as `Policy`.

### [T26] [P1] [TODO] Approval and activation saga steps
- Description: Admin approve/reject endpoint → `PolicyApproved`/`PolicyRejected`. The activation handler sets the active pointer on `PolicyApproved` (if compiled) and emits `PolicyActivated`. Per the hackathon rule, the running snapshot is not hot-swapped; the new version takes effect on restart. Approval can be configured as required for generated and/or edited policies.
- Files/modules: `backend/src/modules/policy/`, `backend/src/modules/admin-api/`
- Depends on: T25, T08
- Acceptance criteria: Tests show that activation of an uncompiled or failed version is rejected, that a running process keeps its old `policyVersion` until restart, that after restart the new version is used, and that a duplicate `PolicyApproved` is a no-op.

### [T27] [P1] [TODO] Tessera-down behavior in Nginx
- Description: Provide an Nginx config that routes to Tessera with the T00-decided behavior when Tessera is unreachable (fail-open upstream route or 503), plus documentation.
- Files/modules: `deploy/nginx/tessera.conf`
- Depends on: T19, T00 (point 8)
- Acceptance criteria: With docker-compose + Nginx, stopping Tessera yields the configured behavior (verified by curl), and with Tessera running all traffic goes through Tessera.

### [T28] [P2] [TODO] Provider-independent AI client with structured output
- Description: An `AiModel` port `generateStructured<T>(prompt, zodSchema) → T` with one concrete adapter. Output that fails schema validation is an error (no prose parsing). Keys come from env.
- Files/modules: `backend/src/modules/analysis/ai/` (or a shared `ai` infrastructure module if used by both analysis and policy-generation)
- Depends on: T03
- Acceptance criteria: Tests (with a fake adapter) show that schema-invalid output → typed error and that valid output is returned typed.

### [T29] [P2] [TODO] Application analysis: source acquisition and secret redaction
- Description: Accept `gitUrl + commit` or a local path. Check out the exact revision into a temp dir and record `sourceRevision`. Redact secrets in `.env`/JSON/YAML configs (keep keys/structure, replace values) before anything is sent externally.
- Files/modules: `backend/src/modules/analysis/`
- Depends on: T03
- Acceptance criteria: Tests show that the checked-out HEAD equals the requested commit and that an `.env` with `DB_PASSWORD=x` becomes `DB_PASSWORD=<redacted>` in the payload sent to the AI client.

### [T30] [P2] [TODO] Application analysis: environment tools (Syft, Trivy)
- Description: Run Syft (SBOM) and Trivy (CVEs) on the source, parse them into structured, source-attributed results, and treat a tool failure as a recorded partial result. Nmap is excluded until a target-scanning scope is defined.
- Files/modules: `backend/src/modules/analysis/environment/`
- Depends on: T29
- Acceptance criteria: Tests on a fixture project produce dependency names and versions plus CVE ids tagged with the tool name. A missing Trivy binary → recorded tool error and analysis continues.

### [T31] [P2] [TODO] Application analysis: AI analysis → `AnalysisCompleted`
- Description: Send redacted source and environment context to the AI client, then produce a versioned model `{sourceRevision, analysisVersion, apiSurface, dependencies, environment, configuration, cves, findings(with evidence)}`. Store it tenant-scoped in Mongo and emit `AnalysisCompleted` / `AnalysisFailed` via the outbox.
- Files/modules: `backend/src/modules/analysis/`
- Depends on: T28, T29, T30, T24
- Acceptance criteria: With a fake AI adapter, the output validates against the schema and is stored with `tenantId`, and the event is emitted exactly once. On AI failure, `AnalysisFailed` is emitted and the active policy is unchanged.

### [T32] [P2] [TODO] Policy generation from analysis
- Description: Handle `AnalysisCompleted`: generate human-readable and structured policy via the AI client (schema-validated), store it as a non-active version, and emit `PolicyGenerated` / `PolicyGenerationFailed`. Idempotent per `analysisVersion`.
- Files/modules: `backend/src/modules/policy-generation/`
- Depends on: T31, T25
- Acceptance criteria: Tests show that a duplicate `AnalysisCompleted` produces one policy version, that invalid AI output → `PolicyGenerationFailed`, and that the active policy is unchanged in both cases.

### [T33] [P2] [TODO] Natural-language policy edit
- Description: Add an admin endpoint that accepts an edited NL policy. It is reinterpreted into structured policy (by the component decided in T00 point 6), then a new version is compiled and enters approval. The API response and docs state explicitly that reinterpretation may lose precision versus code analysis.
- Files/modules: `backend/src/modules/policy-generation/`, `backend/src/modules/admin-api/`
- Depends on: T32, T26, T00 (point 6)
- Acceptance criteria: The response includes the precision-limitation notice, and an edit creates a new pending version without changing the active one.

### [T34] [P2] [TODO] Redis verdict cache
- Description: Cache `StaticVerdict` keyed by `tenantId + policyVersion + method + path + hash(query, relevant headers, body)`. On Redis error, recompute. Never cache JEV-dependent final decisions unless T00 decides otherwise.
- Files/modules: `backend/src/modules/static-analysis/verdict-cache.ts`
- Depends on: T18
- Acceptance criteria: Tests show that identical requests for the same tenant hit the cache, that the same body for a different tenant or policyVersion misses, and that with Redis down results equal the uncached results.

### [T35] [P3] [TODO] Incremental analysis from Git diff
- Description: For a new release, reuse the previous analysis plus `git diff` and recompute only the affected endpoints, dependencies and config.
- Files/modules: `backend/src/modules/analysis/`
- Depends on: T31
- Acceptance criteria: For a fixture diff touching one route file, only that endpoint's entries change in the new analysis version, and the rest are copied from the previous one.

---

## Recommended Next Task

**[T01] Fix `backend` repository linkage.** It has no dependencies, everything else depends on it, and it takes a few minutes. T00 (spec decisions) needs the project owner and can be answered in parallel. It must be resolved before T04/T12/T16/T18.
