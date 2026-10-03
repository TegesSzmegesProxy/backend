import { existsSync } from "node:fs";
import { resolve } from "node:path";

// Variables already set in the process environment win over the .env file.
const envFile = resolve(process.cwd(), ".env");
if (existsSync(envFile)) {
  process.loadEnvFile(envFile);
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

const redisUrl = (): string => requireEnv("REDIS_URL");
const mongoUrl = (): string => requireEnv("MONGO_URL");

const mongoDbName = (): string => process.env["MONGO_DB_NAME"] || "tessera";
const tenantsDbName = (): string => process.env["TENANT_DB_NAME"] || "tenants"
const tenantId = (): string => requireEnv("TENANT_ID");

const requestsCacheSize = (): number => {
  const raw = process.env["REQUESTS_CACHE_SIZE"];
  if (raw === undefined || raw === "") return 10;
  const size = Number(raw);
  if (!Number.isInteger(size) || size < 0) {
    throw new Error(`REQUESTS_CACHE_SIZE must be a non-negative integer, got "${raw}"`);
  }
  return size;
};

export { requireEnv, redisUrl, mongoUrl, mongoDbName, tenantsDbName, tenantId, requestsCacheSize };
