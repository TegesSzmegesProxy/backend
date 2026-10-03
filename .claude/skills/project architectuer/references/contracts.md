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
 verdict: "BENIGN" | "ATTACK"   // derived from the effective threshold, not returned by JEV
 threshold: number              // effective attackProbabilityThreshold the verdict was compared against
 attackProbability: number      // 0-1, JEV's P(yes) to "is this request an attack attempt?"
 score: number                  // 0-3 expected severity level; display/logging only
 confidence: number             // |2 * attackProbability - 1|; display/logging only
}
```
JEV receives only the endpoint, field names/locations/values (never truncated), file metadata and field-attributed static pattern matches. Request identifiers, tenant, client IP, headers and static verdict labels are not sent.
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
```ts
ThresholdConfig {
 attackProbabilityThreshold: number   // T, at least 0 and below 1
 attackProbabilityFloor: number       // in [0, T]
 locked: boolean
}
```
A JEV result is an `ATTACK` only when `attackProbability > effective threshold`; otherwise it is `BENIGN`.
When not locked, the tenant threshold attack rate lowers the effective threshold from `attackProbabilityThreshold` toward `attackProbabilityFloor` (tighten-only); locked thresholds are used as configured.
Severity `score` and `confidence` never affect enforcement.
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
 tenantThresholdRateEWMA: number
 alpha: { up: number, down: number }
}
```
EWMA is asymmetric: `alpha.up` when the observation is above the average, `alpha.down` otherwise (`up > down`), so rates rise fast and recover slowly.
Only JEV `ATTACK/BENIGN` results contribute to the sampling rates. The threshold rate also counts unsampled, statically-safe requests as benign. Static violations/errors contribute to neither.
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
