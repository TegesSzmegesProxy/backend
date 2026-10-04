import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { z } from "zod";

export const BUNDLE_SCHEMA = "tessera.bundle/v2";
export const TOOL_REGISTRY = "tessera.tools/v1";
export const HEARTBEAT_SCHEMA = "tessera.heartbeat/v1";
export const TELEMETRY_SCHEMA = "tessera.telemetry/v1";
export const JEV_CREDENTIAL_SCHEMA = "tessera.jev-credential/v1";

const action = z.enum(["allow", "block"]);
const probability = z.number().finite().min(0).max(1);
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const tenantId = z.string().regex(/^[a-f0-9]{24}$/);
const path = z.string().regex(/^\/(?!.*[?#\s]).*$/).max(1024);
const method = z.enum(["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]);

const step = z.strictObject({
  toolId: z.literal("string_length"),
  contextType: z.literal("field"),
  target: z.string().regex(/^(body|query)\.[^\s]+$/).max(512),
  config: z.strictObject({
    minLength: z.number().int().min(0).max(1_000_000).optional(),
    maxLength: z.number().int().min(0).max(1_000_000).optional(),
  }).refine((value) => value.minLength !== undefined || value.maxLength !== undefined)
    .refine((value) => value.minLength === undefined || value.maxLength === undefined || value.minLength <= value.maxLength),
});

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

export const signedBundleSchema = z.strictObject({
  schemaVersion: z.literal(BUNDLE_SCHEMA),
  tenantId,
  version: hash,
  policyVersion: z.string().min(1),
  runtimeConfig,
  policy: z.strictObject({
    schemaVersion: z.literal("tessera.policy/v1"),
    toolRegistryVersion: z.literal(TOOL_REGISTRY),
    endpoints: z.array(z.strictObject({
      method,
      path,
      steps: z.array(step).min(1).max(100),
    })).min(1).max(500),
  }),
  issuedAt: z.iso.datetime(),
  signature: z.strictObject({
    algorithm: z.literal("Ed25519"),
    keyId: z.string().regex(/^[a-f0-9]{32}$/),
    value: z.string().regex(/^[A-Za-z0-9_-]+$/),
  }),
});

export type SignedBundle = z.infer<typeof signedBundleSchema>;

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
