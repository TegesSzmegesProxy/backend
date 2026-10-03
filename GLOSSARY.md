# Tessera Glossary

- **Tenant**: one protected application and its configuration, policies, and state. All data is tenant-scoped.
- **Proxy (Edge)**: the component that receives client traffic and forwards allowed requests to the upstream application.
- **Upstream**: the protected application server behind Tessera.
- **Normalized request**: the canonical, parsed form of a raw request used by analysis.
- **Tool**: a deterministic check (schema, resource, injection, url, file-magic) that produces a tool result.
- **Static verdict**: the aggregated result of all tools: `SAFE`, `SUSPICIOUS`, `POLICY_VIOLATION`, or `ERROR`.
- **Sampling (N)**: the percentage of `SAFE` requests sent to JEV.
- **Threshold (T)**: the tenant-set trust threshold applied to JEV score and confidence. Independent of N.
- **JEV**: the external classification model that returns a score, a confidence, and a verdict. Not a conversational LLM.
- **Decision**: the final `ALLOW` or `BLOCK`, recorded with the policy version.
- **Policy**: the human-readable and structured rules for one tenant, versioned and immutable once written.
- **Active policy**: the policy version a tenant currently runs on.
- **Attack rate**: the share of JEV-classified requests classified as `ATTACK`, tracked per tenant and per endpoint.
- **EWMA**: the exponentially weighted moving average used to smooth attack-rate observations.
- **Failure behavior**: the tenant-configured behavior when Tessera, static analysis, or JEV fails.
- **Control plane**: the admin and generation side (analysis, policy generation, compilation, approval, activation).
- **Saga**: a choreographed control-plane workflow across modules, driven by events.
