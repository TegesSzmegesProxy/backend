import { z } from "zod";
import { HEARTBEAT_SCHEMA, JEV_CREDENTIAL_SCHEMA, TELEMETRY_SCHEMA } from "./bundle";

const tenantId = z.string().regex(/^[a-f0-9]{24}$/);
const version = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().min(0).max(1_000_000_000);
const contractId = z.string().regex(/^[a-z0-9.-]+\/v[0-9]+$/).max(64);
const probability = z.number().finite().min(0).max(1);

export const jevCredentialSchema = z.strictObject({
  schemaVersion: z.literal(JEV_CREDENTIAL_SCHEMA),
  apiKey: z.string().min(1),
  version: z.number().int().min(1),
  updatedAt: z.iso.datetime(),
});

export const heartbeatSchema = z.strictObject({
  schemaVersion: z.literal(HEARTBEAT_SCHEMA),
  instanceId: z.uuid(),
  proxyVersion: z.string().regex(/^[\w.+-]+$/).max(64),
  supportedBundleSchemas: z.array(contractId).min(1).max(20),
  supportedToolRegistries: z.array(contractId).min(1).max(20),
  health: z.enum(["ok", "degraded"]),
  tenants: z.array(z.strictObject({
    tenantId,
    bundleSource: z.enum(["remote", "last_known_good", "none"]),
    loadedBundleVersion: version.optional(),
  })).min(1).max(100),
});

const endpoint = z.strictObject({
  endpoint: z.string().regex(/^(DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT) \/(?!.*[?#\s]).*$/).max(1040).nullable(),
  decisions: z.strictObject({ allow: count, block: count }),
  staticVerdicts: z.strictObject({ safe: count, suspicious: count, policyViolation: count, error: count }),
  jev: z.strictObject({ sampledSafe: count, attack: count, benign: count, unavailable: count }),
  failureBehaviorApplied: count,
  samplingRate: probability.nullable().optional(),
  attackRateEwma: probability.nullable().optional(),
});

export const telemetryBatchSchema = z.strictObject({
  schemaVersion: z.literal(TELEMETRY_SCHEMA),
  instanceId: z.uuid(),
  batchId: z.uuid(),
  windows: z.array(z.strictObject({
    tenantId,
    bundleVersion: version.nullable(),
    windowStart: z.iso.datetime(),
    endpoints: z.array(endpoint).max(501),
    events: z.strictObject({
      bundleVerificationFailures: count,
      bundlePullFailures: count,
      droppedWindows: count,
    }),
    attackRateEwma: probability.nullable().optional(),
  })).min(1).max(1_440),
});
