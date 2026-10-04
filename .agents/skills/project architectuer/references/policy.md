# Tessera Policy

## Purpose

Tenant-wide security policy defining expected application behavior and the static toolchain used at runtime. Policy generation, editing, compilation, approval and activation all run in the hosted control plane and are exposed through the dashboard. The proxy only consumes the signed, compiled result (see `control-plane.md`).

## Flow

`Code Analysis + Environment + Administrator -> Policy -> Structured Policy -> Compiler -> Toolchain -> Approval -> Activation -> Signed Bundle -> Proxy pull`
Policy may also be imported directly in the supported structured format.

## Scope

One policy belongs to one tenant and covers all endpoints. Endpoint rules contain request-level and field-level behavior. Code analysis automatically discovers endpoints and fields.

## Generation

Tessera uses an external LLM/agent to generate the initial policy from application analysis and environment information. The generated policy is reviewed before activation.
The implementation must not depend on a specific model; examples may include Astra/Fable-class agents.

## Administrator

Administrators use the hosted dashboard to:

* approve generated policies;
* edit the natural-language policy;
* import a policy directly in the supported structured format;
* explicitly select tools.
  Natural-language edits are reinterpreted by the policy-generation LLM before compilation and may lose precision compared with deeper code analysis. This limitation must be exposed to the administrator.

## Unknown structure

Code analysis may add discovered endpoints/fields automatically. The policy compiler determines the required tool configuration for discovered behavior unless the administrator explicitly specifies tools.

## Natural language

Natural language describes expected request/field behavior and security requirements. The policy-generation LLM interprets it into structured policy intent; the compiler then derives the concrete toolchain and dependencies.

## Structured policy

The structured representation is machine-readable and contains at minimum tenant rules, endpoint rules, field rules, selected/configured tools and relevant JEV context. It is the compiler input.
The LLM must return structured output conforming to the defined schema; do not depend on parsing prose.

## Compiler

The compiler transforms policy intent into a static-analysis toolchain. It infers tool selection, configuration, ordering and dependencies unless explicitly specified by the administrator.
Compiler output may configure registered tools but must not invent unsupported tool types or executable runtime code. The compiler must know which tools and bundle schema versions the target proxy version supports. The proxy re-validates on its side and rejects bundles referencing tools it does not have.

## Approval

Policy activation is approval-gated. Approval requirements may be configurable, including requiring approval for generated policies and/or edits. Failed generation, compilation or validation leaves the active policy unchanged.

## Versioning

Every activated policy has an immutable version/hash. Runtime decisions use exactly one active version. Keep human-readable policy and compiled toolchain associated with the same version. On activation the control plane builds and signs one bundle (tenant runtime config + compiled policy) under that version. The proxy applies it on its next restart.

## Update model

For a new application release, code analysis may use the Git diff plus previous analysis/policy instead of reanalyzing the full codebase. Policy changes produce a new version and activation event.

## Invariants

`Human policy = intent`
`Structured policy = machine-readable intent`
`Compiler = toolchain derivation`
`Toolchain = runtime static-analysis configuration`
`Active policy = approved version`
Never partially activate generated policy. Never replace the active policy after a failed compilation/validation. Never distribute an unsigned bundle.

