---
name: tessera-architecture
description: Architecture for Tessera, a multi-tenant TypeScript/Express runtime security proxy with a hosted control plane. Use when implementing or changing request enforcement, static analysis, JEV decisions, adaptive sampling, policy generation, application analysis, storage, caching, failure behavior, the dashboard/admin API, API keys, policy distribution or anything that crosses the proxy/control-plane boundary.
---
# Tessera Architecture
## Goal
Tessera is a security proxy placed in front of an existing application.
Clients send requests to Tessera; Tessera analyzes them and forwards only allowed requests to the real application server.
Tessera is split into two deployables:
- **Proxy (data plane)**, deployed on the client's server: enforcement only.
- **Control plane**, hosted by us: dashboard/admin API, analysis, policy generation, compilation, approval and activation. The proxy pulls signed, versioned policy bundles from it using an API key.

A client-side **collector** (CI step or CLI) gathers and redacts code and environment context and uploads it to the control plane.
Optimize for the hackathon: fast implementation, simple deployability, clear security boundaries, and working end-to-end behavior over production-scale complexity.
## Stack
- TypeScript + Express
- MongoDB: persistent application/policy/configuration data
- Redis: runtime cache
- JEV: external decision/classification model
- Nginx points traffic at Tessera; Tessera forwards allowed traffic upstream
- Proxy and control plane talk over versioned HTTPS APIs only; the proxy always initiates
- Frontend technology is out of architectural scope
JEV is a decision model that accepts structured state/questions and returns typed decisions with probabilities/confidence. Treat it as a decision dependency, not as a conversational LLM.
## Architecture
Read only the reference relevant to the current task:
- [system.md](references/system.md) — boundaries and components
- [runtime.md](references/runtime.md) — request lifecycle and enforcement
- [static-analysis.md](references/static-analysis.md) — Runner, Tools, Aggregator
- [policy.md](references/policy.md) — policy generation and compilation
- [analysis.md](references/analysis.md) — codebase/application analysis
- [adaptation.md](references/adaptation.md) — sampling, thresholds, feedback
- [operations.md](references/operations.md) — storage, cache, failures, deployment
- [contracts.md](references/contracts.md) — component data contracts
- [control-plane.md](references/control-plane.md) — hosted control plane, deployables, API keys, signed policy bundles, pull model, collector, telemetry
Do not load unrelated references unless the task crosses their boundary.
## Core flow
`Client -> Tessera Proxy -> Normalize -> Static Analysis`
Static result:
`Policy violation -> BLOCK`
`Suspicious -> configurable handling`
`OK -> Sampling`
Sampling result:
`Not sampled -> ALLOW`
`Sampled -> JEV -> confidence -> threshold -> ALLOW/BLOCK`
Allowed requests are forwarded:
`Tessera -> Real Application`
Responses return through Tessera to the client.
## Core invariants
- Tessera is the enforcement boundary.
- The backend never decides whether Tessera should forward a blocked request.
- Static analysis always precedes JEV.
- Obvious policy violations do not require JEV.
- Sampling can reduce JEV calls but cannot bypass static policy violations.
- Sampling percentage `N` and confidence threshold `T` are independent concepts.
- JEV produces evidence for a decision; it does not replace deterministic security checks.
- Runtime enforcement must not synchronously depend on codebase analysis or on the hosted control plane.
- Control-plane failure or unreachability must not corrupt or stop the active runtime policy; the proxy runs on its last known good bundle.
- The proxy executes only signed bundles it has verified, containing only tools in its own registry.
- The control plane never connects into the client network; secrets, raw request contents and unredacted source never leave it.
- Cache failure must cause recomputation, not an unsafe decision.
- Security behavior must be explicit and observable.
- Multi-tenant data must never cross tenant boundaries.
## Policy
Application understanding comes from:
`Codebase + Dependencies + Environment + API Surface + CVEs + Administrator Intent`
This produces a human-readable policy, then a structured representation, then compiled runtime policy/tool configuration.
Collection and redaction run client-side; AI analysis, generation and compilation run in the hosted control plane. The proxy only receives the compiled, signed result.
Policies may require human approval.
Administrators may edit policy in natural language. Edited policy is reinterpreted by the policy-generation LLM (not JEV); the UI/API must make this limitation explicit.
Policies may be edited while a protected application release is running. Each edit creates a new version that must be recompiled before activation. Activated versions take effect when the proxy next restarts and pulls its bundle.
## Failure behavior
Users configure failure behavior where security semantics require a choice.
At minimum support configurable behavior for:
- Tessera/proxy failure
- suspicious request when JEV is unavailable
- static-analysis failure
- no valid policy bundle available at proxy startup (control plane unreachable and no last known good)
Redis failure should not prevent analysis; recompute instead.
Do not silently introduce new fail-open/fail-closed behavior.

## Implementation rules
First identify the owning deployable (proxy, control plane or collector), then the owning component, then modify that component.
Do not duplicate responsibilities across components.
Keep request-path code small and synchronous in its control flow; expensive or optional work must be explicit.
Prefer structured contracts over parsing free-form model output.
Keep tenant identity explicit at every persistence/cache boundary.
Do not introduce abstractions solely for theoretical scalability during the hackathon.
When existing code conflicts with this architecture, inspect tests and current behavior before changing it.
When a security or architectural decision is unspecified, ask instead of inventing one.
## Open architectural decision
`N` is the adaptive sampling percentage.
`T` is the JEV confidence/trust threshold.
Addaptive controller is agile to recnet attack rate and suspicious code, but based on user set values