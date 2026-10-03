# Tessera Control Plane and Distribution

## Purpose

Defines the split between the hosted control plane and the client-side proxy, and the only interfaces between them: policy distribution, analysis upload and telemetry. Read this whenever a change touches the dashboard/admin API, API keys, policy pull, signing, the collector, or anything that crosses the network between us and the client.

## Deployables

One repository, three entry points sharing `shared/` (contracts and generic infrastructure only):

| Deployable | Runs at | Owns |
|---|---|---|
| **Proxy** (data plane) | Client server, behind Nginx | `edge`, `core`, `feedback`: enforcement, static analysis, sampling, JEV client, decision, history, adaptive state, local copy of active configuration |
| **Control** (control plane) | Hosted by us | `control`, AI part of `analysis`: dashboard/admin API, organizations, tenants, API keys, analysis, policy generation, compilation, approval, activation, distribution API, telemetry intake |
| **Collector** | Client CI (e.g. GitHub Action) or CLI | Source acquisition, secret redaction, environment tools (Syft/Trivy): the parts of `analysis` that must see the client's code and environment |

The proxy and control each stay a modular monolith internally. Neither imports the other's modules; they share only `shared/contracts` and generic `shared/` code. Why: the proxy is the enforcement boundary on someone else's server and must stay small, with no LLM SDKs, no analysis tooling and no dashboard code.

## Direction of connections

The proxy and collector always initiate connections to control. Control never connects into the client network. The proxy needs only outbound HTTPS to control and to JEV.

## Organizations and tenants

An organization (a customer) owns one or more tenants (protected applications). Dashboard users belong to an organization and only see that organization's tenants. Control is multi-tenant across customers, so tenant isolation rules in `operations.md` apply to every control-plane store, queue and API. Organization-level auth for dashboard users is an open decision; ask rather than inventing it.

## API keys

- A **deployment key** authenticates one proxy deployment. Server-side it is bound to an explicit set of tenants that deployment may pull. Control derives the tenant set from the key, never from request parameters. A request for a tenant outside the key's set gets `403`.
- A **collector key** authenticates analysis uploads for specific tenants. It can upload analysis context only and cannot pull policy.
- Control stores only a hash of each key (never the plaintext) plus metadata: id, organization, tenants, scopes, created/revoked. A key is shown once at creation. Keys are revocable from the dashboard.
- The proxy and collector read their keys from environment variables or deployment secrets.

## Active configuration bundle

What the proxy pulls is one immutable, versioned bundle per tenant:

```ts
ActiveBundle {
 schemaVersion: number      // bundle format version the proxy must support
 tenantId: string
 version: string            // hash over canonical content; equals policyVersion
 runtimeConfig: {           // routing, upstreamUrl, failure behavior, thresholds (+ locks), unknownEndpointBehavior, sampling bounds
   ...
 }
 policy: Policy             // compiled policy/toolchain from contracts.md
 activatedAt: string
 signature: string          // control-plane signature over canonical { schemaVersion, tenantId, version, runtimeConfig, policy }
}
```

Runtime config and compiled policy travel together under one version, so the proxy never mixes a policy with another version's thresholds or failure behavior. Secrets are never part of a bundle.

## Signing and verification

Control signs every activated bundle with a private key that only control holds (Ed25519 is the default choice). The proxy is configured with the matching public key via env and, before storing or using a bundle, verifies:

1. the signature;
2. `tenantId` is in the set this deployment expects;
3. `schemaVersion` is supported;
4. the bundle validates against the contract schemas;
5. every tool id exists in the proxy's own tool registry and every tool config validates.

Any failure rejects the whole bundle and keeps the last valid one. Why: a compromised or buggy control plane must not be able to push malformed configuration to every customer, and the proxy is the final authority over what it executes. This complements, and does not replace, the compiler's own validation.

## Pull model

- `GET /v1/tenants/{tenantId}/active-bundle` with the deployment key. The response includes `ETag: version`.
- The proxy pulls at startup. Activation takes effect only on restart (see `policy.md`), so the runtime snapshot is never hot-swapped.
- The proxy may poll (with `If-None-Match`) to detect a newer activated version and report "restart required" (via log and telemetry). Polling never changes the running snapshot.
- Verified bundles are persisted in the proxy's local store as **last known good**.

## Startup and outage behavior

| Situation | Proxy behavior |
|---|---|
| Control reachable, valid bundle | Verify, persist as last known good, load snapshot |
| Control unreachable or erroring | Load last known good from the local store; log the degraded state |
| Bundle fails verification | Reject it, keep last known good, log, report via telemetry |
| No valid bundle and no last known good for a tenant | Tenant-configured/startup failure behavior (open decision T00.4); never invent fail-open |

A control-plane outage must never stop or change enforcement of an already-loaded policy.

## Analysis upload

The collector runs on the client side, per release. It:

1. checks out the exact revision;
2. redacts secrets;
3. runs environment tools;
4. uploads one structured, redacted context package with `sourceRevision`, together with the source files the analysis needs.

Control stores the package tenant-scoped and starts the analysis saga. Upload is the explicit trust boundary where the customer's code leaves their network. Redaction happens before upload, never on the control side, and the dashboard/docs must state what is uploaded.

## Telemetry

- The proxy may send batched decision summaries and health (e.g. counts per verdict, recent BLOCK summaries, active version, degraded state) to control for the dashboard.
- Telemetry is best-effort, asynchronous and off the request path. A telemetry failure drops or buffers data and never affects a decision.
- Summaries follow the logging redaction rules: no field values, bodies, auth headers or cookies.
- Adaptive state (EWMA) stays local to the proxy and is authoritative there. Telemetry only reports it.

## Cross-boundary communication

Proxy ↔ control and collector → control use plain authenticated HTTPS request/response with versioned JSON contracts. Sagas, the outbox/inbox and the Redis broker are internal to control; never extend them across the network. Version every cross-boundary contract (`/v1/...`, `schemaVersion`) because proxies in the field upgrade later than control.

## Invariants

The proxy never synchronously depends on control in the request path. Control never connects into the client. The proxy executes only signed, verified bundles containing tools it knows. A failed pull or verification never replaces the last valid configuration. API keys are scoped, hashed at rest and revocable. Secrets, raw request contents and unredacted source never leave the client. Tenant identity on control is derived from authenticated credentials, never from client-supplied parameters.
