# Tessera System Architecture

## Purpose

Tessera is a multi-tenant runtime security proxy: `Client -> Nginx -> Tessera Proxy -> Application`. The protected application requires no SDK integration. Tessera analyzes HTTP requests and forwards only allowed requests.

Tessera has two deployables. The **proxy** (data plane) runs on the client's server. The **control plane** is hosted by us and holds the dashboard/admin API, analysis, policy generation, compilation and activation. A client-side **collector** uploads redacted code and environment context. See `control-plane.md` for the boundary between them.

## Stack

TypeScript + Express; MongoDB for persistent state; Redis for short-lived runtime context/cache; JEV for dynamic classification. Frontend is out of scope.

## Deployment

One proxy process can serve multiple tenants of the same customer. A tenant is identified by `domain/IP + path` routing context. Each tenant has its own protected application configuration and policy. The hosted control plane serves many customers (organizations), each owning one or more tenants.

## Supported traffic

HTTP requests and file uploads. File analysis may inspect magic bytes and related file properties. Responses are not analyzed. Tessera never modifies requests; it only analyzes, blocks, or forwards them unchanged.

## Endpoint model

An endpoint is identified by `HTTP method + path`. Every endpoint has a policy containing:

* request-level tools and JEV context;
* field-level policies, where each request field has its own tools and JEV context.
  File fields may use file-specific tools such as magic-byte validation.

## Request flow

`Request -> Normalize -> Static Analysis -> BLOCK / SUSPICIOUS / OK`
`OK -> Sampling -> ALLOW`
`Sampled -> JEV -> Classification + Score + Confidence -> Threshold -> ALLOW/BLOCK`
Allowed requests are forwarded to the configured upstream application.

## Static analysis

Static analysis is the first security layer. A policy defines the group of tools executed for an endpoint/request/field and the context supplied to JEV. Tools cover schema, malicious input, injection, URL/networking, resource abuse, semantic anomalies and file validation. Auth is not enforced by Tessera; Tessera only detects/block malicious behavior.

## Verdicts

Static analysis should expose a small stable verdict model such as `SAFE`, `SUSPICIOUS`, `POLICY_VIOLATION`, `ERROR`. Policy violations can terminate the request without JEV.

## JEV

JEV is the expensive contextual classifier. Tessera supplies normalized request data plus relevant static-tool evidence and configured policy context. JEV returns classification, a fixed maliciousness score `1-6`, and confidence. Tessera converts that result into the final enforcement decision using the configured threshold.

## Threshold

`T` is the configured trust/risk threshold for interpreting the JEV score/confidence. Threshold is user-controlled per tenant. Keep threshold logic separate from sampling logic.

## Sampling

`N` is the sampling probability/percentage. Sampling is configurable per endpoint: for example `N=10%` means each eligible request to that endpoint has a 10% chance of JEV analysis. Unsampled requests are allowed. Sampling never bypasses static policy violations.

## Adaptive control

Sampling is controlled at endpoint level, and attack rate is measured per tenant and per endpoint. The adaptive controller may adjust endpoint sampling based on the tenant and endpoint observed attack rates. `T` remains user-controlled and is not automatically changed unless explicitly configured in a future design.

## Request history

Redis keeps only the last 3 requests as short-lived context for decision making. History is tenant-scoped and keyed by client IP; it is context, not a cache of previous request verdicts. Do not use it as the source of truth for policy or security state.

## Cache

Redis is an optimization/context store, not authoritative state. Cache/history failures must never corrupt policy or create an unsafe decision. MongoDB remains the durable source of configuration and policy.

## Multi-tenancy

Every tenant has isolated policies, endpoint definitions, runtime configuration, analysis results, metrics and request history. Tenant identity must be explicit at every storage/cache boundary. Cross-tenant data use is forbidden.

## Policy

Policy is application-specific and endpoint-specific. Policy lifecycle: `Code/Environment Analysis -> Generated Policy -> Human Review/Edit -> Classification/Toolchain Generation -> Compiled Policy -> Activate`. Human edits are accepted in natural language and then interpreted/classified before becoming active configuration.

## Application analysis

Analysis runs per application release, typically from CI such as GitHub Actions. A later analysis may use only the Git diff instead of reprocessing the entire codebase. Analysis produces context for policy generation, including API surface, dependencies, environment/configuration and CVEs.

## Control/runtime separation

Code analysis, policy generation and compilation are control-plane operations running in the hosted control plane. Request processing must not synchronously depend on them or on the control plane being reachable. Runtime uses the currently active compiled configuration: a signed bundle pulled from the control plane at startup and kept locally as last known good.

## Configuration

An active policy/configuration has a version/hash. Tenant runtime config (routing, upstream, failure behavior, thresholds, sampling bounds) and compiled policy are distributed together as one versioned bundle. Policies may be edited in the dashboard while the proxy is running. Each edit creates a new version that must be recompiled before it can be activated; the proxy picks up the active version when it restarts. Runtime must never mix policy versions within one decision.

## Failure behavior

The user configures tenant-level behavior for major failures. Relevant failures include Tessera/proxy, static analysis, JEV and upstream. JEV failure stops dynamic analysis and follows tenant configuration. Redis failure removes historical context/cache optimization but must not silently change policy.

## Ownership

`Edge = transport/forwarding`; `Normalizer = canonical request`; `Tools = deterministic evidence`; `Aggregator = static verdict`; `JEV = classification`; `Orchestration = final decision`; `Control Plane (hosted) = tenants, keys, dashboard, policy/config generation, activation, distribution`; `Collector (client-side) = source, redaction, environment tools`; `MongoDB = durable state (per deployable)`; `Redis = short-lived context`.

## Invariants

Never modify requests. Never bypass static blocking through sampling. Never let JEV directly forward traffic. Never mix tenant data. Never use Redis as authoritative policy state. Never invent fail-open/fail-closed behavior where tenant configuration is required. Never let the proxy depend on control-plane availability in the request path, or execute an unverified bundle.

