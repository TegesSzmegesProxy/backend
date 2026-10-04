import { z } from "zod";
import { bytes, defineTool, durationMs, fieldNames, noConfig, positiveCount } from "./common";

export const dataLeakageTools = {
  pii_in_request: defineTool({
    id: "pii_in_request",
    displayName: "PII in request",
    category: "data_leakage",
    contextType: "field",
    description: "Rejects checksum-valid card numbers, PESEL, US SSN and IBAN in fields not meant to hold them.",
    config: z.strictObject({
      expectedFields: z.strictObject({
        payment_card: fieldNames().default(["cardnumber", "pan", "ccnumber", "creditcard", "card"]),
        pesel: fieldNames().default(["pesel", "nationalid"]),
        us_ssn: fieldNames().default(["ssn", "socialsecuritynumber", "nationalid"]),
        iban: fieldNames().default(["iban", "accountnumber", "bankaccount"]),
      }).prefault({}).describe("Fields where each identifier is expected, so finding it there is not a leak."),
    }),
  }),
  response_leak: defineTool({
    id: "response_leak",
    displayName: "Response leak",
    category: "data_leakage",
    contextType: "full",
    description: "On the response pass, rejects stack traces, SQL errors and debug pages; flags internal addresses and paths.",
    config: noConfig(),
  }),
  response_size_anomaly: defineTool({
    id: "response_size_anomaly",
    displayName: "Response size anomaly",
    category: "data_leakage",
    contextType: "full",
    description: "On the response pass, rejects oversized responses and flags responses far above the route's baseline.",
    config: z.strictObject({
      baselineWindowMs: durationMs().default(3_600_000),
      minSamples: positiveCount(10_000).default(20).describe("No baseline, no judgement."),
      maxSamples: positiveCount(10_000).default(500),
      minFactorOverMedian: z.number().finite().min(1).max(10_000).default(10),
      minStdDeviations: z.number().finite().min(0).max(100).default(4),
      minAnomalousBytes: bytes().default(262_144).describe("Smaller responses are never worth flagging."),
      maxResponseBytes: bytes().default(52_428_800),
    }).refine((value) => value.minSamples <= value.maxSamples, "minSamples must not exceed maxSamples"),
  }),
  secrets_in_payload: defineTool({
    id: "secrets_in_payload",
    displayName: "Secrets in payload",
    category: "data_leakage",
    contextType: "field",
    description: "Rejects live credentials (private keys, cloud and SaaS tokens) pasted into ordinary fields; flags likely ones.",
    config: z.strictObject({
      credentialFields: fieldNames().default(["password", "passwd", "apikey", "token", "accesstoken", "secret", "clientsecret", "privatekey", "publickey", "credentials"]).describe("Fields that are supposed to carry a credential (login forms, API key settings)."),
    }),
  }),
} as const;
