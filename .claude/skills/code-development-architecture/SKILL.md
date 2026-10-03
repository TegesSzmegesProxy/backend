---
name: tessera-development
description: Development rules for Tessera, a modular monolith TypeScript/Express runtime security proxy. Use when writing or changing Tessera code, module boundaries, control-plane sagas, events, tenant isolation, or testing.
---

# Tessera Development

## Architecture

Tessera is a **modular monolith**, not a microservice system.
Keep one deployable application/process while enforcing strong internal module boundaries.
Each module owns its domain logic, persistence access, validation, and public interfaces.
Do not bypass module boundaries by importing internal implementation details.

## Module boundaries

Prefer:
`module -> own domain/application logic -> own infrastructure`
Cross-module access should use explicit public APIs, commands, queries, or events.
Do not directly access another module's database models/repositories.
Avoid shared "utils" that contain domain logic; shared code must be genuinely generic.

## Dependencies

Prefer a directed dependency graph.
Higher-level orchestration may depend on domain modules; domain modules should not depend on HTTP/Express.
Infrastructure depends on domain/application interfaces where practical.
Never introduce circular module dependencies.

## Request path

Keep the runtime path explicit:
`HTTP -> normalization -> tenant/endpoint -> policy -> static analysis -> sampling -> JEV -> decision -> upstream`
Do not place control-plane operations or expensive background work in the request path unless explicitly required.

## Saga choreography

Long-running multi-step workflows use **choreographed sagas**.
There is no central workflow coordinator that owns the entire saga.
Modules react to domain events and emit new events representing completed state transitions.
Example:
`AnalysisCompleted -> PolicyGeneration -> PolicyGenerated -> Compilation -> PolicyCompiled -> Approval -> Activation`.

Each module:

1. consumes events relevant to it;
2. validates the event;
3. performs its local transaction;
4. persists its local state;
5. emits the next event.

Events describe facts (`PolicyGenerated`, `AnalysisCompleted`), not commands disguised as facts.
Do not make events depend on internal class names or database models.

Sagas apply only to control-plane workflows (analysis, policy generation, compilation, approval, activation). The runtime request path never runs a saga.

## Saga rules

Every saga step must be independently retryable and idempotent. Use a Mongo-backed inbox (unique `consumer + eventId`) for idempotency and a Mongo outbox for publication. Do not use NATS JetStream or any other external message broker.
Persist enough state to determine whether an event was already processed.
Do not assume event delivery is exactly-once.
Handlers must tolerate duplicate, delayed, and out-of-order events where the workflow permits it.
Failures must produce explicit failure events/state rather than silently stopping the saga.
Compensation is a domain action, not a database rollback across modules.

## Transactions

Use local database transactions for local state changes.
Never assume one transaction can cover multiple modules.
When a state change and event publication must be atomic, use an outbox/event-publication mechanism rather than publishing before persistence.

## Events

Events should contain stable identifiers and versions, for example:
`eventId, eventType, version, tenantId, aggregateId, occurredAt, payload`.
Keep payloads minimal; consumers should not require unrelated internal state.
Version events when their schema changes.

## Tenant isolation

Every domain operation must preserve `tenantId`.
Repositories, caches, events, policies, and module state must remain tenant-scoped.
Never infer tenant identity from mutable business data when an explicit tenant context exists.

## TypeScript

Use strict TypeScript.
Prefer explicit domain types over `any`.
Validate external input at boundaries.
Separate transport DTOs from domain objects when their semantics differ.
Do not leak Express request/response objects into domain logic.

## Error handling

Distinguish:

* expected domain errors;
* validation errors;
* infrastructure failures;
* external dependency failures.
  Do not swallow errors.
  Return safe, explicit failure states.
  Follow Tessera's architecture files for security-sensitive failure behavior.

## Testing

Test only most important part of modules. 
For saga steps, test duplicate delivery and partial failure.
For request-path code, test final `ALLOW/BLOCK` behavior and tenant isolation.

## Code organization

Organize code by domain/module rather than by global technical layer where practical.
A module should make its public API obvious.
Keep controllers thin; application services coordinate; domain logic stays in domain modules; infrastructure implements persistence/external interfaces.

## Change process

Before coding:

1. Identify the owning module.
2. Read the relevant architecture reference.
3. Identify affected contracts/events.
4. Check whether the change crosses a saga boundary.
5. Preserve existing invariants.

Implement the smallest change consistent with the architecture.
Do not introduce abstractions or infrastructure without a concrete need.
Do not silently change security semantics.

## Architecture references

Use:
This file holds the global rules.
`system.md` for boundaries.
`runtime.md` for request flow.
`static-analysis.md` for tools.
`policy.md` for policy lifecycle.
`analysis.md` for application analysis.
`adaptation.md` for adaptive control.
`operations.md` for storage/failures/deployment.
`contracts.md` for data contracts.

When implementation and architecture disagree, inspect existing code/tests first. If the intended behavior is ambiguous and architecture-critical, ask rather than inventing it.

