import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { z } from "zod";
import { TOOL_REGISTRY_V2, TOOL_REGISTRY_V3, V3_TOOLS, isToolId, toolContract } from "./tools";

/** Endpoint steps only, with the v1 policy shape. */
export const BUNDLE_SCHEMA_V2 = "tessera.bundle/v2";
/** Global, environment and endpoint scopes with JEV context (`tessera.policy/v3`). */
export const BUNDLE_SCHEMA_V3 = "tessera.bundle/v3";
/** Every bundle schema this proxy verifies, newest first (sent as Tessera-Bundle-Schemas). */
export const SUPPORTED_BUNDLE_SCHEMAS = [BUNDLE_SCHEMA_V3, BUNDLE_SCHEMA_V2] as const;
export const POLICY_SCHEMA_V3 = "tessera.policy/v3";
/** The first registry: `string_length` only. Still accepted, so dashboards that only compile v1 keep working. */
export const TOOL_REGISTRY_V1 = "tessera.tools/v1";
/** The newest registry this proxy executes; see TOOL_CONTRACTS and docs/tool-registry.json. */
export const TOOL_REGISTRY = TOOL_REGISTRY_V3;
/** Every registry this proxy executes, newest first (sent as Tessera-Tool-Registries). */
export const SUPPORTED_TOOL_REGISTRIES = [TOOL_REGISTRY_V3, TOOL_REGISTRY_V2, TOOL_REGISTRY_V1] as const;
export const HEARTBEAT_SCHEMA = "tessera.heartbeat/v1";
export const TELEMETRY_SCHEMA = "tessera.telemetry/v1";
export const JEV_CREDENTIAL_SCHEMA = "tessera.jev-credential/v1";

/** JEV context bounds of `tessera.policy/v3`, in characters. */
export const MAX_SCOPE_JEV_CONTEXT = 1_500;
export const MAX_ENDPOINT_JEV_CONTEXT = 1_500;
export const MAX_FIELD_JEV_CONTEXT = 500;

const action = z.enum(["allow", "block"]);
const probability = z.number().finite().min(0).max(1);
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const tenantId = z.string().regex(/^[a-f0-9]{24}$/);
const path = z.string().regex(/^\/(?!.*[?#\s]).*$/).max(1024);
const method = z.enum(["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]);
const V1_TOOLS: ReadonlySet<string> = new Set(["string_length"]);

/** What a step's target names: "body.x" / "query.x" for a field tool, the upload field for a file tool, nothing for the full request. */
const TARGETS = {
  field: /^(body|query)\.[^\s]+$/,
  file: /^[^\s]+$/,
} as const;

/**
 * Targets that name every field of a location ("body.*", "query.*") or every field and upload ("*"). Only the global
 * and environment scopes may use them: they apply to requests whose fields the policy cannot list.
 */
export const WILDCARD_TARGETS: ReadonlySet<string> = new Set(["*", "body.*", "query.*"]);

// The tool, context type, target and configuration of every step are checked against the tool's contract, so a
// bundle naming an unknown tool or a configuration the proxy can't execute is rejected before anything runs.
const stepSchema = (allowWildcards: boolean) => z.strictObject({
  toolId: z.string().min(1).max(64),
  contextType: z.enum(["field", "file", "full"]),
  target: z.string().min(1).max(512).optional(),
  config: z.record(z.string(), z.unknown()),
}).superRefine((value, context) => {
  if (!isToolId(value.toolId)) {
    context.addIssue({ code: "custom", path: ["toolId"], message: `Unknown tool: ${value.toolId.slice(0, 64)}` });
    return;
  }
  const contract = toolContract(value.toolId);
  if (value.contextType !== contract.contextType) {
    context.addIssue({ code: "custom", path: ["contextType"], message: `${contract.id} runs on ${contract.contextType} context` });
  }
  if (contract.contextType === "full") {
    if (value.target !== undefined) context.addIssue({ code: "custom", path: ["target"], message: "Whole-request tools take no target" });
  } else if (value.target === undefined) {
    context.addIssue({ code: "custom", path: ["target"], message: `${contract.id} needs a ${contract.contextType} target` });
  } else if (WILDCARD_TARGETS.has(value.target)) {
    const fits = contract.contextType === "field" || value.target === "*";
    if (!allowWildcards || !fits) {
      context.addIssue({ code: "custom", path: ["target"], message: "Wildcard targets apply only to global and environment steps" });
    }
  } else if (!TARGETS[contract.contextType].test(value.target)) {
    context.addIssue({ code: "custom", path: ["target"], message: `${contract.id} needs a ${contract.contextType} target` });
  }
  const config = contract.config.safeParse(value.config);
  if (!config.success) {
    for (const issue of config.error.issues) {
      context.addIssue({ code: "custom", path: ["config", ...issue.path], message: issue.message });
    }
  }
});
const step = stepSchema(false);
const scopeStep = stepSchema(true);

const runtimeConfig = z.strictObject({
  upstreamUrl: z.url().refine((value) => {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password;
  }),
  failureBehavior: action,
  unknownEndpointBehavior: action,
  routing: z.strictObject({ pathPrefix: path }),
  thresholds: z.strictObject({
    requestTimeoutMs: z.number().int().min(100).max(120_000),
    maxRequestBodyBytes: z.number().int().min(0).max(104_857_600),
  }),
  samplingRate: probability,
  decision: z.strictObject({
    sampling: z.strictObject({ minN: probability, maxN: probability }),
    jev: z.strictObject({
      attackProbabilityThreshold: probability,
      attackProbabilityFloor: probability,
      locked: z.boolean(),
    }),
    onStaticAnalysisError: action,
    onSuspiciousJevUnavailable: action,
    onSampledJevUnavailable: action,
  }),
}).refine((value) => value.decision.sampling.minN <= value.samplingRate && value.samplingRate <= value.decision.sampling.maxN)
  .refine((value) => value.decision.sampling.minN > 0 ||
    (value.samplingRate === 0 && value.decision.sampling.maxN === 0))
  .refine((value) => value.decision.jev.attackProbabilityFloor <= value.decision.jev.attackProbabilityThreshold);

const signature = z.strictObject({
  algorithm: z.literal("Ed25519"),
  keyId: z.string().regex(/^[a-f0-9]{32}$/),
  value: z.string().regex(/^[A-Za-z0-9_-]+$/),
});

const policyV1 = z.strictObject({
  schemaVersion: z.literal("tessera.policy/v1"),
  toolRegistryVersion: z.enum(SUPPORTED_TOOL_REGISTRIES),
  endpoints: z.array(z.strictObject({
    method,
    path,
    steps: z.array(step).min(1).max(100),
  })).min(1).max(500),
}).superRefine((policy, context) => {
  // a tool added in a later registry is unknown to the dashboards and proxies that compiled this one
  const needs = (toolId: string) =>
    policy.toolRegistryVersion === TOOL_REGISTRY_V1 && !V1_TOOLS.has(toolId) ? (V3_TOOLS.has(toolId) ? TOOL_REGISTRY_V3 : TOOL_REGISTRY_V2)
    : policy.toolRegistryVersion === TOOL_REGISTRY_V2 && V3_TOOLS.has(toolId) ? TOOL_REGISTRY_V3
    : undefined;
  policy.endpoints.forEach((endpoint, endpointIndex) => endpoint.steps.forEach((value, stepIndex) => {
    const registry = needs(value.toolId);
    if (registry) {
      context.addIssue({ code: "custom", path: ["endpoints", endpointIndex, "steps", stepIndex, "toolId"], message: `${value.toolId} needs ${registry}` });
    }
  }));
});

const jevContext = (max: number) => z.string().min(1).max(max).nullable();
const scope = z.strictObject({
  steps: z.array(scopeStep).max(100),
  jevContext: jevContext(MAX_SCOPE_JEV_CONTEXT),
});

/**
 * `tessera.policy/v3`: global and environment steps run on every request, endpoint steps on their endpoint. When the
 * same tool and target appear in more than one scope, the most specific one runs (endpoint, then environment, then
 * global). JEV context is data describing legitimate traffic, never instructions.
 */
const policyV3 = z.strictObject({
  schemaVersion: z.literal(POLICY_SCHEMA_V3),
  toolRegistryVersion: z.literal(TOOL_REGISTRY_V3),
  global: scope,
  environment: scope.extend({ environmentSnapshotId: z.string().regex(/^[a-f0-9]{24}$/).nullable() }),
  endpoints: z.array(z.strictObject({
    method,
    path,
    steps: z.array(step).max(100),
    jevContext: jevContext(MAX_ENDPOINT_JEV_CONTEXT),
    fieldContexts: z.array(z.strictObject({
      target: z.string().regex(TARGETS.field).max(512),
      jevContext: z.string().min(1).max(MAX_FIELD_JEV_CONTEXT),
    })).max(200),
  })).max(500),
});

const bundleV2 = z.strictObject({
  schemaVersion: z.literal(BUNDLE_SCHEMA_V2),
  tenantId,
  version: hash,
  policyVersion: z.string().min(1),
  runtimeConfig,
  policy: policyV1,
  issuedAt: z.iso.datetime(),
  signature,
});

const bundleV3 = z.strictObject({
  schemaVersion: z.literal(BUNDLE_SCHEMA_V3),
  tenantId,
  version: hash,
  policyVersion: z.string().min(1),
  runtimeConfig,
  policy: policyV3,
  issuedAt: z.iso.datetime(),
  signature,
});

export const signedBundleSchema = z.discriminatedUnion("schemaVersion", [bundleV3, bundleV2]);

export type SignedBundle = z.infer<typeof signedBundleSchema>;
export type SignedBundleV2 = z.infer<typeof bundleV2>;
export type SignedBundleV3 = z.infer<typeof bundleV3>;
export type PolicyStep = z.infer<typeof step>;
export type BundleRuntimeConfig = z.infer<typeof runtimeConfig>;

/** Canonical JSON compatible with the dashboard's signed JSON payload. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
}

export class BundleVerifier {
  private readonly publicKey: KeyObject;
  private readonly keyId: string;

  constructor(publicKeyPem: string, private readonly expectedTenantId: string) {
    this.publicKey = createPublicKey(publicKeyPem.replace(/\\n/g, "\n"));
    if (this.publicKey.asymmetricKeyType !== "ed25519") throw new Error("Bundle public key must be Ed25519");
    this.keyId = createHash("sha256").update(this.publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 32);
  }

  verify(raw: unknown): SignedBundle {
    const bundle = signedBundleSchema.parse(raw);
    if (bundle.tenantId !== this.expectedTenantId) throw new Error("Bundle tenant does not match deployment");
    const { signature, ...payload } = bundle;
    if (signature.keyId !== this.keyId || !verify(null, Buffer.from(canonicalJson(payload)), this.publicKey, Buffer.from(signature.value, "base64url"))) {
      throw new Error("Bundle signature is invalid");
    }
    const { version, issuedAt, ...content } = payload;
    const expectedVersion = createHash("sha256").update(canonicalJson(content)).digest("hex");
    if (version !== expectedVersion) throw new Error("Bundle version hash is invalid");
    const endpoints = new Set<string>();
    for (const endpoint of bundle.policy.endpoints) {
      const key = `${endpoint.method} ${endpoint.path}`;
      if (endpoints.has(key)) throw new Error(`Duplicate policy endpoint: ${key}`);
      endpoints.add(key);
    }
    return bundle;
  }
}
