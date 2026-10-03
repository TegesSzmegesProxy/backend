# Tessera Static Analysis

## Purpose

First runtime security layer. Runs policy-selected deterministic tools before sampling/JEV and produces structured evidence plus one aggregated verdict.

## Flow

`Request -> Runner -> Tools -> Aggregator -> BLOCK / JEV / Sampling`

## Runner

Runner receives normalized request + active endpoint policy, builds the execution plan and runs selected tools. Tools may execute in parallel or serially when dependencies require ordering. The runner must preserve declared tool dependencies.

## Tool model

Each tool is an independent module with a common interface and structured input/output. Policies compose existing tools; the Toolchain Generator selects/configures them. Do not duplicate security logic inside the Runner.

## Tool groups

`schema`: field shape, type, requiredness, size, format. `auth`: inspect auth-related request properties; never authenticate users or replace application auth. `injection`: SQL/command/template/XSS/path and other malicious-input checks. `url`: URL, protocol, host/port and networking checks. `resource`: size/resource-abuse checks. `anomaly`: semantic/contextual anomalies. File tools may inspect uploads, magic bytes and metadata.

## Context

Field/schema tools normally receive only their assigned field. A tool may declare additional request/context dependencies when required. There is no requirement for generic request-level tools to inspect fields individually.

## Tool results

Minimum result: `tool`, `status`, `verdict`, `evidence`. Verdicts: `SAFE | SUSPICIOUS | POLICY_VIOLATION | ERROR`. Tools may return `SUSPICIOUS` without a blocking rule; JEV can interpret the evidence.

## Errors

Any tool error makes the aggregated result `ERROR`, and Tessera applies the tenant's configured static-analysis failure behavior. Never convert tool failure to `SAFE`.

## Aggregator

Combines all results and preserves compact evidence for JEV. Priority: `ERROR > POLICY_VIOLATION > SUSPICIOUS > SAFE`. `ERROR` -> configured failure behavior. `POLICY_VIOLATION` -> block. `SUSPICIOUS` -> JEV. Only all-`SAFE` results reach sampling.

## Dependencies

Tools may declare prerequisites/dependencies. Independent tools should run concurrently; dependent tools run after required results are available. The Runner owns scheduling, not individual tools.

## Determinism

Prefer deterministic checks for schema, limits, known attack patterns, file signatures and explicit policy rules. Individual tools never invoke JEV or make forwarding decisions.

## JEV context

Aggregator emits compact structured evidence and relevant context only. Avoid redundant raw tool output. JEV receives context after aggregation, not directly from each tool.

## Generated toolchains

Policy defines which tools run and with what configuration/context. Toolchain generation composes registered tools; generated configuration must not create arbitrary executable code unless explicitly supported by the architecture.

## Invariants

Static analysis always precedes JEV. Static blocking cannot be bypassed by sampling. Every suspicious result reaches JEV. Tool errors produce `ERROR`, handled by configured failure behavior. Tools never modify requests, forward traffic, or directly call JEV.

