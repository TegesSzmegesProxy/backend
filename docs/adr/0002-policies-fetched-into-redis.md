# 0002: Policies are fetched into Redis by `tessera fetch`

## Status

Accepted, 2026-10-04. Supersedes ADR-0001.

## Context

The proxy pulled the active bundle from the dashboard at every startup and kept
a verified copy on disk. Operators could not choose when an activated policy
reached a running proxy, and every process kept its own copy.

The dashboard now distributes scoped policies (`tessera.bundle/v3`: global,
environment and endpoint steps with tool configurations and JEV context;
dashboard ADR-0020). These are larger and more consequential.

## Decision

- **Fetching.** Only the `tessera fetch` command contacts the dashboard for
  bundles. It:
  1. pulls the active bundle with the deployment key;
  2. verifies it (signature, content hash, tenant, every step against its tool
     contract);
  3. builds every tool it names;
  4. stores the signed bundle in Redis, under `tessera:{tenantId}:policy:`.

  The bundle is stored as `bundle:{version}`, with an `active` pointer and the
  `previous` version kept, in one MULTI. A failed fetch changes nothing.
- **Redis is the last known good store.** Redis content is not trusted. Every
  load re-verifies the signed bundle before it is used.
- **Startup.** Ingress loads and verifies the active bundle from Redis before
  opening the port. If Redis is unreachable, nothing was fetched, or the stored
  bundle fails verification, the proxy exits and asks the operator to run
  `tessera fetch`. The proxy never starts without a verified policy.
- **Running proxies.**
  - After a fetch, the proxy publishes on `tessera:{tenantId}:policy:updates`,
    and running proxies also poll the `active` pointer every 30 seconds.
  - A proxy verifies and builds the new bundle, then swaps it in between
    requests.
  - A bundle that changes the upstream is not swapped in; the proxy reports
    that a restart is required.
  - A bundle that fails to load keeps the running policy.
  - Redis outages never drop the policy in memory.
- **Reporting.** Once a minute the proxy asks the dashboard whether a newer
  bundle is active, and only reports it. It never stores or applies what it
  sees.
- **Scopes at runtime.** Global and environment steps run on every request,
  including unlisted endpoints when `unknownEndpointBehavior` is `allow`. When
  the same tool and target appear in more than one scope, the endpoint step
  wins, then the environment one. Wildcard field targets (`body.*`, `query.*`,
  `*`) are accepted only in those two scopes.

## Consequences

- Deploying a proxy needs Redis and a `tessera fetch` before the first start.
- Dashboard outages never block a restart, because the policy is local.
- Activated policies reach proxies only when an operator fetches them.
- All proxy processes of a tenant that share a Redis run the same policy, and
  switch together.
