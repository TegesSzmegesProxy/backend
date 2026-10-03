# Tessera Contracts
## Purpose
Canonical typed contracts between Tessera components. Keep them minimal, versioned and tenant-scoped. Model prose is never a runtime contract. Contracts that cross the proxy/control-plane network boundary (`ActiveBundle`, analysis upload, telemetry) are defined in `control-plane.md` and must stay backward-compatible, because deployed proxies upgrade later than the control plane.
## IDs
`tenantId` identifies the protected application. `endpoint = "METHOD /path"` (e.g. `"POST /login"`, path without query string). `policyVersion` identifies the exact active policy. `analysisVersion` identifies application analysis.
## Normalized request
```ts
NormalizedRequest {
 requestId: string
 tenantId: string
 endpoint: string
 clientIp: string
 query: object
 headers: object
 body: unknown
 fields: RequestField[]
 files: RequestFile[]
 timestamp: string
}
```
Only include data required by downstream components. Forward the original request unchanged.
## RequestField
```ts
RequestField {
 name: string
 value: unknown
 type: string
 location: string
 metadata?: object
}
```
## RequestFile
```ts
RequestFile {
 field: string
 filename: string
 contentType?: string
 size: number
 magicBytes?: string
 metadata?: object
}
```
## Tool contract
Every tool defines its own input contract and receives only the information it requires. The Runner must satisfy that contract and may provide declared dependencies/context. Tools must not assume access to the full request.
## Tool result
```ts
ToolResult {
 tool: string
 status: "SUCCESS" | "ERROR"
 verdict: "SAFE" | "SUSPICIOUS" | "POLICY_VIOLATION" | "ERROR"
 evidence: unknown
}
```
Each tool sets its own verdict. A tool that throws or times out returns `status: "ERROR", verdict: "ERROR"`. A tool does not produce the final request decision.
## Static verdict
```ts
StaticVerdict {
 verdict: "SAFE" | "SUSPICIOUS" | "POLICY_VIOLATION" | "ERROR"
 results: ToolResult[]
 evidence: unknown
}
```
Aggregation priority: `ERROR > POLICY_VIOLATION > SUSPICIOUS > SAFE`. Tool errors produce `ERROR`, handled by configured failure behavior. Suspicious requests proceed to JEV.
## JEV input
```ts
JevInput {
 tenantId: string
 endpoint: string
 policyVersion: string
 requestContext: unknown
 staticEvidence: unknown
 recentRequests: unknown[]
}
```
`requestContext` and `staticEvidence` contain only information required by the active tenant policy.
## JEV result
```ts
JevResult {
 verdict: "BENIGN" | "ATTACK"
 score: 1 | 2 | 3 | 4 | 5 | 6
 confidence: number
}
```
`score` = maliciousness. `confidence` = confidence in the classification.
## Final decision
```ts
Decision {
 action: "ALLOW" | "BLOCK"
 reason: string
 tenantId: string
 endpoint: string
 policyVersion: string
 staticVerdict: StaticVerdict
 sampled: boolean
 jev?: JevResult
}
```
Only `ALLOW` reaches the upstream application.
## JEV thresholds
Each tenant configures:
`maliciousScoreThreshold`
`confidenceThreshold`
A JEV result is an `ATTACK` only when both configured conditions are satisfied:
`score > maliciousScoreThreshold && confidence > confidenceThreshold`

If the score exceeds `maliciousScoreThreshold` but confidence does not exceed `confidenceThreshold`, the result is `ALLOW`.
Thresholds may be locked by configuration. Exact boundary operators are part of the active configuration.
## Sampling
```ts
SamplingConfig {
 probabilityN: number
 minN: number
 maxN: number
}
```
Sampling is endpoint-scoped. `N` is adaptively controlled within `[minN, maxN]`.
## Adaptive state
```ts
AdaptiveState {
 tenantAttackRateEWMA: number
 endpointAttackRateEWMA: Record<string, number>
 alpha: number
}
```
Only JEV `ATTACK/BENIGN` results contribute to attack-rate feedback.
## Policy
```ts
Policy {
 tenantId: string
 version: string
 endpoints: EndpointPolicy[]
}
EndpointPolicy {
 method: string
 path: string
 requestTools: ToolConfig[]
 fields: FieldPolicy[]
 jevContext: unknown
 sampling: SamplingConfig
}
FieldPolicy {
 name: string
 tools: ToolConfig[]
 jevContext: unknown
}
```
Policy is tenant-wide; endpoint and field rules are contained inside it.
## Cache
Verdict-cache identity must include at least `tenantId + endpoint + requestBodyHash` and every other request component affecting analysis. Never reuse results across tenants or incompatible policy versions.
Request history uses `tenantId + clientIp` and stores at most 3 recent requests.
## Versioning
Every active policy has an immutable version/hash. Every decision references the exact policy version used. The policy version equals the version of the signed bundle it was distributed in.
## Validation
Validate contracts at component boundaries. Missing/invalid required fields are errors. Never infer security semantics from malformed model/tool output.
