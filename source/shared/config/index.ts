import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";
import { assertTenantId } from "../storage/tenant-id";

// Empty values count as unset, so `FOO=` in a .env file falls back to the default.
const optional = <T extends z.ZodType>(schema: T) =>
  z.preprocess((value) => (value === "" ? undefined : value), schema);

const envSchema = z.object({
  REDIS_URL: z.string().min(1),
  TENANT_ID: z.string().regex(/^[a-f0-9]{24}$/),
  DASHBOARD_API_URL: z.url().refine((value) => {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password;
  }),
  DEPLOYMENT_API_KEY: z.string().min(1),
  BUNDLE_PUBLIC_KEY: z.string().min(1),
  PORT: optional(z.coerce.number().int().min(0).max(65535).default(62197)),
});

interface ProxyConfig {
  tenantId: string;
  redisUrl: string;
  dashboard: { url: string; apiKey: string; publicKey: string };
  ingress: { port: number };
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
    tenantId: assertTenantId(env.TENANT_ID),
    redisUrl: env.REDIS_URL,
    dashboard: { url: env.DASHBOARD_API_URL, apiKey: env.DEPLOYMENT_API_KEY, publicKey: env.BUNDLE_PUBLIC_KEY },
    ingress: { port: env.PORT },
  };
}

export { loadConfig };
export type { ProxyConfig };
