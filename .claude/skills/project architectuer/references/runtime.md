# Tessera Runtime

## Purpose

Defines the request-path behavior. `Ingress -> Normalize -> Tenant/Endpoint -> Policy -> Static Analysis -> Sampling -> JEV -> Decision -> Upstream`.

## Ingress

Accept HTTP requests and buffered file uploads. Tessera never modifies an allowed request. Forwarded request must preserve method, path, headers, query and body.

## Tenant/endpoint

Resolve the tenant from configured domain/IP + path routing. Resolve endpoint by `HTTP method + path`. Every endpoint has request-level policy plus field-level policies.

## Policy

Load one active policy version for the whole request. Policy defines tools and JEV context for the endpoint and each relevant field. Unknown endpoint passes through by default; this may be configurable.

## Normalization

Create one canonical request representation containing method, path, query, relevant headers, body/fields, client IP and file metadata. Preserve original request data for forwarding.

## Static analysis

Run policy-selected tools. Request tools inspect the request; field tools inspect assigned fields; file tools may inspect magic bytes and other properties. Tools return structured evidence.

## Static verdict

Aggregator returns `SAFE | SUSPICIOUS | POLICY_VIOLATION | ERROR`.
`POLICY_VIOLATION -> BLOCK`.
`SUSPICIOUS -> JEV`.
`SAFE -> Sampling`.
`ERROR -> configured failure behavior`.
Every suspicious result goes to JEV.

## Sampling

`N` is endpoint sampling probability. Each eligible request independently has probability `N` of JEV analysis. `not sampled -> ALLOW`; `sampled -> JEV`. Sampling never bypasses static blocking. Sampling uses secure randomness.

## Adaptive sampling

Runtime attack rate is maintained per tenant and per endpoint. The Adaptive Controller uses EWMA of attack rate to adjust endpoint sampling rather than reacting directly to a single measurement. `T` is separate and remains user-controlled.

## Request history

Redis stores the last 3 requests for each `tenant + client IP`. History is contextual evidence only, never a cached verdict or policy source. Redis failure means dynamic analysis continues without history.

## JEV

Send the minimum required structured context: normalized request, relevant static evidence, endpoint/field policy context and recent request history. JEV returns `classification`, maliciousness `score 1-6`, and `confidence`. Validate the response before use.

## Threshold

`T` operates on JEV confidence. JEV score describes maliciousness; confidence determines whether the classification is trusted enough for enforcement. Exact comparison/mapping belongs to `contracts.md`. A JEV result whose score exceeds the threshold but whose confidence does not is `ALLOW`.

## Decision

Orchestration combines static verdict, sampling, JEV result, confidence threshold, policy version and failure state into `ALLOW | BLOCK`. Only `ALLOW` reaches upstream.

## Forwarding

Forward allowed requests unchanged to the configured application upstream. Responses are returned to the client unchanged; response security analysis is out of scope.

## Failure

Tenant configuration controls behavior for major failures, including Tessera/proxy, static analysis and JEV. Redis failure removes history only. Never invent fail-open/fail-closed behavior.

## Observability

Record tenant, endpoint, policy version, static verdict, sampling result, JEV classification/score/confidence when used, threshold, final decision and failure state. Never log unnecessary secrets or sensitive request contents.

## Invariants

Static analysis always precedes JEV. Static blocking cannot be bypassed. Unsampled requests do not invoke JEV. Tessera never modifies requests. JEV never forwards requests. One request uses one policy version. Redis is never authoritative.

