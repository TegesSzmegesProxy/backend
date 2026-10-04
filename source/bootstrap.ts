import { TypeSafeClient } from "@typesafe-ai/sdk";
import { IngressServer } from "./edge";
import { Normalizer } from "./edge/normalizer";
import { Runner, type ExecutionPlan } from "./core/static-analysis/runner";
import { Aggregator } from "./core/static-analysis/aggregator";
import { JevClient } from "./core/jev";
import { DecisionOrchestrator, type DecisionConfig, type RuntimeConfig } from "./core/decisionOrchestrator";
import { Sampler } from "./core/sampling";
import Xss from "./core/static-analysis/tools/injection/xss";
import SqlInjection from "./core/static-analysis/tools/injection/sqlinjection";
import { AdaptiveControl } from "./feedback";
import { Broker } from "./shared/broker";
import { MongoStorage, RedisStorage } from "./shared/storage";
import { loadConfig } from "./shared/config";

const REDIS_STARTUP_TIMEOUT_MS = 5_000;

// Placeholder values until per-tenant runtime config arrives with the policy bundle (TODO T04/T20/T31/T35).
// N is a probability (0-1); thresholds are on the JEV attack probability (0-1) and tighten toward the floor under attack.
const PLACEHOLDER_RUNTIME_CONFIG: RuntimeConfig = {
  sampling: { probabilityN: 0.1, minN: 0.01, maxN: 1 },
  threshold: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false },
};
const PLACEHOLDER_PLAN: ExecutionPlan = [
  { tool: new Xss(), target: "login" },
  { tool: new SqlInjection(), target: "login" },
];

const FAILURE_POLICY: DecisionConfig = {
  staticAnalysisError: "BLOCK",
  suspiciousWhenJevUnavailable: "BLOCK",
  sampledWhenJevUnavailable: "ALLOW",
};

// Redis only holds non-authoritative context, so an unreachable Redis must not block startup.
// node-redis keeps retrying in the background and the dependent features recover on their own.
async function connectOptional(name: string, connect: () => Promise<void>): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(() => {
      console.warn(`[bootstrap] ${name} not reachable yet, continuing without it`);
      resolve();
    }, REDIS_STARTUP_TIMEOUT_MS);
  });
  try {
    await Promise.race([connect(), timeout]);
  } catch (error) {
    console.warn(`[bootstrap] ${name} failed to connect, continuing without it:`, error);
  } finally {
    clearTimeout(timer);
  }
}

/** Composition root: every long-lived instance is created and owned here, and shut down in reverse. */
async function main(): Promise<void> {
  const config = loadConfig();

  // Infrastructure.
  // MongoDB is the durable source of truth: failing to connect aborts startup.
  // `mongo` is the top-level database of the app.
  const mongo = new MongoStorage({ url: config.mongo.url, dbName: config.mongo.dbName });
  const tenantsDb = new MongoStorage({ url: config.mongo.url, dbName: config.mongo.tenantsDbName });
  // await mongo.connect();
  const redis = new RedisStorage({ url: config.redisUrl });
  const broker = new Broker({ url: config.redisUrl });
  await Promise.all([
    connectOptional("redis", () => redis.connect()),
    connectOptional("broker", () => broker.connect()),
  ]);
  const tenantRedis = redis.tenant(config.tenantId);

  // Request path.
  const orchestrator = new DecisionOrchestrator(
    {
      jev: new JevClient(new TypeSafeClient({ apiKey: config.jev.apiKey }), tenantRedis.sub("jev-verdict-cache")),
      adaptive: new AdaptiveControl(),
      sampler: new Sampler(),
      configFor: () => PLACEHOLDER_RUNTIME_CONFIG,
    },
    FAILURE_POLICY,
  );
  const ingress = new IngressServer(
    {
      normalizer: new Normalizer(),
      runner: new Runner(),
      aggregator: new Aggregator(),
      orchestrator,
      planFor: () => PLACEHOLDER_PLAN,
      recentRequests: tenantRedis.sub("ingress-requests-cache"),
    },
    { tenantId: config.tenantId, ...config.ingress },
  );
  await ingress.start();

  const shutdown = async (): Promise<void> => {
    await ingress.stop();
    await Promise.allSettled([broker.disconnect(), redis.disconnect(), mongo.disconnect(), tenantsDb.disconnect()]);
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("[bootstrap] failed to start:", error);
  process.exit(1);
});
