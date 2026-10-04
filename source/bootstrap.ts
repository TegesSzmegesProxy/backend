import { IngressServer } from "./edge";
import { Normalizer } from "./edge/normalizer";
import { Runner } from "./core/static-analysis/runner";
import { Aggregator } from "./core/static-analysis/aggregator";
import { CredentialManager } from "./core/jev";
import { DecisionOrchestrator, type DecisionConfig, type RuntimeConfig } from "./core/decisionOrchestrator";
import { Sampler } from "./core/sampling";
import { AdaptiveControl } from "./feedback";
import { RedisStorage } from "./shared/storage";
import { loadConfig } from "./shared/config";
import { BundleVerifier, type BundleRuntimeConfig } from "./shared/contracts";
import { ActivePolicy, BundleFetcher, PoliciesNotFetchedError, PolicySnapshot, PolicyStore, PolicyWatcher } from "./core/policy";
import { ProxyReporter } from "./shared/telemetry";
import { version } from "../package.json";

const REDIS_STARTUP_TIMEOUT_MS = 5_000;

/** Policies live in Redis, so the proxy cannot start without it. */
async function connectRequired(connect: () => Promise<void>): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      connect(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Redis did not connect within ${REDIS_STARTUP_TIMEOUT_MS} ms`)), REDIS_STARTUP_TIMEOUT_MS);
      }),
    ]);
  } catch (error) {
    throw new Error(`Redis is unavailable at REDIS_URL; the proxy reads its policies from Redis (${error instanceof Error ? error.message : error})`);
  } finally { clearTimeout(timer); }
}

function runtimeFor(config: BundleRuntimeConfig): RuntimeConfig {
  const decision = config.decision;
  return {
    sampling: { probabilityN: config.samplingRate, minN: decision.sampling.minN, maxN: decision.sampling.maxN },
    threshold: {
      attackProbabilityThreshold: decision.jev.attackProbabilityThreshold,
      attackProbabilityFloor: decision.jev.attackProbabilityFloor,
      locked: decision.jev.locked,
    },
  };
}

function failuresFor(config: BundleRuntimeConfig): DecisionConfig {
  const decision = config.decision;
  return {
    staticAnalysisError: decision.onStaticAnalysisError.toUpperCase() as DecisionConfig["staticAnalysisError"],
    suspiciousWhenJevUnavailable: decision.onSuspiciousJevUnavailable.toUpperCase() as DecisionConfig["suspiciousWhenJevUnavailable"],
    sampledWhenJevUnavailable: decision.onSampledJevUnavailable.toUpperCase() as DecisionConfig["sampledWhenJevUnavailable"],
  };
}

/**
 * The policies `tessera fetch` stored in Redis are verified and compiled before the ingress port opens. Without them
 * the proxy does not start: it never fetches on its own, and never runs without a verified policy.
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const verifier = new BundleVerifier(config.dashboard.publicKey, config.tenantId);
  const redis = new RedisStorage({ url: config.redisUrl });
  await connectRequired(() => redis.connect());
  const tenant = redis.tenant(config.tenantId);
  const store = new PolicyStore(tenant.sub("policy"));
  // tools that look across requests keep their state in Redis; while it is down they report ERROR
  const load = (raw: unknown) => new PolicySnapshot(verifier.verify(raw), (tenantId) => redis.tenant(tenantId));

  const raw = await store.loadActive();
  if (raw === null) throw new PoliciesNotFetchedError(config.tenantId);
  let snapshot: PolicySnapshot;
  try {
    snapshot = load(raw);
  } catch (error) {
    throw new Error(`The policies stored in Redis cannot be used (${error instanceof Error ? error.message : error}). Run \`tessera fetch\`, then start the proxy again.`);
  }
  const fetcher = new BundleFetcher({ tenantId: config.tenantId, apiBaseUrl: config.dashboard.url, deploymentKey: config.dashboard.apiKey }, verifier);
  const policy = new ActivePolicy(snapshot, fetcher);
  console.info(`[bootstrap] running policy ${snapshot.version}`, snapshot.summary);

  // Verdicts are cached per running bundle, so a swapped-in policy never reuses another policy's verdicts.
  const credential = new CredentialManager(
    config.dashboard.url,
    config.dashboard.apiKey,
    (credentialVersion) => ({
      get: (key) => tenant.sub(policy.snapshot.version).sub(`jev-${credentialVersion}`).get(key),
      set: (key, value, ttlSeconds) => tenant.sub(policy.snapshot.version).sub(`jev-${credentialVersion}`).set(key, value, ttlSeconds),
    }),
  );
  await credential.refresh();
  const orchestrator = new DecisionOrchestrator({
    jev: credential,
    adaptive: new AdaptiveControl(),
    sampler: new Sampler(),
    configFor: () => runtimeFor(policy.snapshot.bundle.runtimeConfig),
  }, () => failuresFor(policy.snapshot.bundle.runtimeConfig));
  const reporter = new ProxyReporter({
    tenantId: config.tenantId,
    apiBaseUrl: config.dashboard.url,
    deploymentKey: config.dashboard.apiKey,
    proxyVersion: version,
  }, policy);
  const ingress = new IngressServer({
    normalizer: new Normalizer(),
    runner: new Runner(),
    aggregator: new Aggregator(),
    orchestrator,
    policy,
    reporter,
  }, { tenantId: config.tenantId, port: config.ingress.port });
  await ingress.start();
  const watcher = new PolicyWatcher(store, policy, load);
  await watcher.start();
  reporter.start();
  const credentialTimer = setInterval(() => { void credential.refresh(); }, 60_000);
  credentialTimer.unref();

  const shutdown = async (): Promise<void> => {
    clearInterval(credentialTimer);
    await ingress.stop();
    await watcher.stop();
    await reporter.stop();
    await redis.disconnect();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  if (error instanceof PoliciesNotFetchedError) console.error(`[bootstrap] ${error.message}`);
  else console.error("[bootstrap] failed to start:", error);
  process.exit(1);
});
