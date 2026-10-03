import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";

// Empty values count as unset, so `FOO=` in a .env file falls back to the default.
const optional = <T extends z.ZodType>(schema: T) =>
  z.preprocess((value) => (value === "" ? undefined : value), schema);

const envSchema = z.object({
  REDIS_URL: z.string().min(1),
  MONGO_URL: z.string().min(1),
  MONGO_DB_NAME: optional(z.string().default("tessera")),
  TENANT_DB_NAME: optional(z.string().default("tenants")),
  TENANT_ID: z.string().min(1),
  UPSTREAM_URL: z.string().min(1),
  TYPESAFE_API_KEY: z.string().min(1),
  PORT: optional(z.coerce.number().int().min(0).max(65535).default(62197)),
  REQUESTS_CACHE_SIZE: optional(z.coerce.number().int().min(0).default(10)),
});

interface ProxyConfig {
  tenantId: string;
  redisUrl: string;
  mongo: { url: string; dbName: string; tenantsDbName: string };
  ingress: { port: number; upstreamUrl: string; requestsCacheSize: number };
  jev: { apiKey: string };
}

/**
 * Reads and validates the proxy configuration once, at startup. Only the composition root calls
 * this; every other component receives the values it needs through its constructor.
 * Variables already set in the process environment win over the .env file.
 */
function loadConfig(envFile: string = resolve(process.cwd(), ".env")): ProxyConfig {
  if (existsSync(envFile)) {
    process.loadEnvFile(envFile);
  }
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(`Invalid configuration:\n${z.prettifyError(parsed.error)}`);
  }
  const env = parsed.data;
  return {
    tenantId: env.TENANT_ID,
    redisUrl: env.REDIS_URL,
    mongo: { url: env.MONGO_URL, dbName: env.MONGO_DB_NAME, tenantsDbName: env.TENANT_DB_NAME },
    ingress: { port: env.PORT, upstreamUrl: env.UPSTREAM_URL, requestsCacheSize: env.REQUESTS_CACHE_SIZE },
    jev: { apiKey: env.TYPESAFE_API_KEY },
  };
}

export { loadConfig };
export type { ProxyConfig };
