# Tessera Operations

## Purpose

Defines storage, caching, failure behavior and deployment for both deployables. Optimize for the hackathon: one process per deployable, simple deployment, durable configuration and predictable degraded modes.

## Deployment

**Proxy (client server):** `Nginx -> Tessera Proxy -> Application`. Runs as a Linux process or in Docker, with a local MongoDB and Redis. Needs outbound HTTPS to the control plane and to JEV only.
**Control plane (hosted by us):** one process with its own MongoDB and Redis, plus the external AI API used for analysis and generation. It serves the dashboard/admin API and the distribution API.
**Collector:** runs in the client's CI or as a CLI; it is stateless.
One process per deployable is the current model; horizontal scaling is out of scope. Both deployables are built from one repository with separate entry points.

## MongoDB

MongoDB is the durable source of truth within each deployable.
**Control-plane MongoDB** is authoritative for organizations, tenants, tenant configuration, API-key hashes, policies, policy versions, compiled toolchains, signed bundles, application-analysis results, environment context and telemetry.
**Proxy MongoDB** holds the last known good verified bundle per tenant, EWMA/attack-rate state and other persistent runtime state. It is a verified local copy of configuration, never an editing surface; configuration changes come only from a newly pulled, verified bundle.

## Policy persistence

The control plane stores both the human-readable policy and the compiled policy/toolchain, associated with one immutable policy version/hash. Activation is an atomic pointer update in the control plane. The proxy persists a pulled bundle only after verifying it, and replaces its last known good copy atomically.

## Startup

On startup the proxy pulls each tenant's active bundle from the control plane, verifies it and persists it. If the control plane is unreachable, it loads the last known good bundle from its local MongoDB (see `control-plane.md`). Runtime must not start using partially loaded or mixed policy versions.

## Redis

Redis provides short-lived runtime state and optimizations. Store recent request context and reusable verdicts. Request history is limited to the last 3 requests per `tenant + client IP`.

## Verdict cache

Cache reusable verdicts using a request/body hash plus endpoint identity. For equivalent tenant/endpoint/request-body inputs, the cached verdict may be reused because the analyzed input is identical. Cache keys must include tenant and endpoint boundaries.
Cache is an optimization; policy/configuration remains authoritative in MongoDB.

## Adaptive state

EWMA and attack-rate state must survive proxy restarts and is therefore persisted in the proxy's MongoDB. Redis may hold temporary copies for performance. The control plane only receives it as telemetry.

## Analysis

The collector gathers and redacts context client-side. Application analysis then runs in the control plane through an external AI/model API. Results are stored in the control-plane MongoDB with source revision and analysis version for traceability.

## Credentials

Secrets are provided through environment variables or deployment secrets, never stored in policies, bundles or MongoDB.
**Proxy:** JEV API key, deployment API key, control-plane URL, bundle-signing public key.
**Control plane:** AI API keys, bundle-signing private key.
**Collector:** collector API key.
The control plane stores only hashes of the API keys it issues. That is a verifier, not a stored credential.

## Logging

Write structured, serializable logs to files. Logs should contain enough metadata to reconstruct security behavior but must not contain secrets or unnecessary sensitive request contents.

## Failure behavior

**MongoDB failure:** durable configuration/state cannot be trusted; follow configured service failure behavior and do not silently invent security semantics. **Redis failure:** continue without cache/history optimization. **JEV failure:** stop dynamic analysis and apply tenant-configured behavior. **Static-analysis failure:** apply configured behavior. **Upstream failure:** return the upstream error; Tessera does not replace the application. **AI analysis failure:** leave the currently active policy unchanged. **Control-plane unreachable (proxy side):** keep enforcing the loaded snapshot; at startup use last known good; with neither, apply the configured startup failure behavior. **Bundle verification failure:** reject the bundle and keep last known good. **Telemetry failure:** drop or buffer; never affects decisions.

## Configuration continuity

A valid active policy remains usable while the hosted control plane or external AI services are unavailable. Failed generation, compilation, pull or verification must never replace the last valid active policy.

## Restart/recovery

After restart, the proxy pulls (or falls back to last known good for) active tenant bundles and reloads persistent adaptive state from its MongoDB. Rebuild only non-authoritative Redis state.

## Security

Tenants are isolated by namespace, not by query filters: each tenant has its own MongoDB database (`{dbName}_t_{tenantId}`, via `MongoStorage.tenantDb`), and every Redis key is prefixed `tessera:{tenantId}:` (via `RedisStorage.tenant`, since Redis has no cheap per-tenant database). Repositories are only a storage abstraction and do not enforce scope themselves. Tenant ids are validated (`A-Za-z0-9_-`, max 40). Cache or persistence bugs must never allow one tenant's policy, request history or verdict to be used for another tenant. The same namespace rules apply in the control plane. There, the tenant is additionally derived from the authenticated API key or dashboard session, and an organization can never reach another organization's tenants.

## Operational invariants

`Control-plane MongoDB = source of truth for configuration`; `Proxy MongoDB = last known good bundle + adaptive state`; `Redis = cache/context`; `bundle version = atomic runtime configuration`; `logs = structured files`; `one process per deployable`; `Nginx = external entry point`; `upstream application = unchanged backend`; `proxy initiates all control-plane traffic`.

