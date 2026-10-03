# Tessera Operations

## Purpose

Defines storage, caching, failure behavior and deployment. Optimize for the hackathon: one Tessera process, simple deployment, durable configuration and predictable degraded modes.

## Deployment

`Nginx -> Tessera -> Application`. Tessera may run directly as a Linux process or in Docker. MongoDB, Redis and external AI/JEV services are separate dependencies. One Tessera process is the current deployment model; horizontal scaling is out of scope.

## MongoDB

MongoDB is the durable source of truth. Store tenant configuration, policies, policy versions, compiled toolchains, application-analysis results, environment context, adaptive configuration, EWMA/attack-rate state, metrics and other persistent runtime state.

## Policy persistence

Store both the human-readable policy and compiled policy/toolchain in MongoDB. Associate them with one immutable policy version/hash. Activation must be atomic from the runtime perspective.

## Startup

On startup Tessera loads the active configuration/policy for tenants from MongoDB. Runtime must not start using partially loaded or mixed policy versions.

## Redis

Redis provides short-lived runtime state and optimizations. Store recent request context and reusable verdicts. Request history is limited to the last 3 requests per `tenant + client IP`.

## Verdict cache

Cache reusable verdicts using a request/body hash plus endpoint identity. For equivalent tenant/endpoint/request-body inputs, the cached verdict may be reused because the analyzed input is identical. Cache keys must include tenant and endpoint boundaries.
Cache is an optimization; policy/configuration remains authoritative in MongoDB.

## Adaptive state

EWMA and attack-rate state must survive Tessera restarts and therefore be persisted in MongoDB. Redis may hold temporary copies for performance.

## Analysis

Application analysis is performed synchronously through an external AI/model API. Results are stored in MongoDB with source revision and analysis version for traceability.

## Credentials

AI/JEV API keys and other secrets are provided through environment variables or deployment secrets. Never store credentials in policies or MongoDB.

## Logging

Write structured, serializable logs to files. Logs should contain enough metadata to reconstruct security behavior but must not contain secrets or unnecessary sensitive request contents.

## Failure behavior

**MongoDB failure:** durable configuration/state cannot be trusted; follow configured service failure behavior and do not silently invent security semantics. **Redis failure:** continue without cache/history optimization. **JEV failure:** stop dynamic analysis and apply tenant-configured behavior. **Static-analysis failure:** apply configured behavior. **Upstream failure:** return the upstream error; Tessera does not replace the application. **AI analysis failure:** leave the currently active policy unchanged.

## Configuration continuity

A valid active policy remains usable while the control plane or external AI services are unavailable. Failed generation/compilation must never replace the last valid active policy.

## Restart/recovery

After restart, reload active tenant policies/configuration and persistent adaptive state from MongoDB. Rebuild only non-authoritative Redis state.

## Security

Tenants are isolated by namespace, not by query filters: each tenant has its own MongoDB database (`{dbName}_t_{tenantId}`, via `MongoStorage.tenantDb`), and every Redis key is prefixed `tessera:{tenantId}:` (via `RedisStorage.tenant`, since Redis has no cheap per-tenant database). Repositories are only a storage abstraction and do not enforce scope themselves. Tenant ids are validated (`A-Za-z0-9_-`, max 40). Cache or persistence bugs must never allow one tenant's policy, request history or verdict to be used for another tenant.

## Operational invariants

`MongoDB = durable source of truth`; `Redis = cache/context`; `policy version = atomic runtime configuration`; `logs = structured files`; `one Tessera process`; `Nginx = external entry point`; `upstream application = unchanged backend`.

