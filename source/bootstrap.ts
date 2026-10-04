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
import { BundleVerifier } from "./shared/contracts";
import { BundleManager, PolicySnapshot } from "./core/policy";
import { ProxyReporter } from "./shared/telemetry";
import { version } from "../package.json";

const REDIS_STARTUP_TIMEOUT_MS = 5_000;

async function connectOptional(connect: () => Promise<void>): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      connect(),
      new Promise<void>((resolve) => { timer = setTimeout(resolve, REDIS_STARTUP_TIMEOUT_MS); }),
    ]);
  } catch (error) {
    console.warn("[bootstrap] Redis unavailable; cache will be bypassed:", error);
  } finally { clearTimeout(timer); }
}

/** The signed bundle is loaded before opening the ingress port. */
async function main(): Promise<void> {
  const config = loadConfig();
  const verifier = new BundleVerifier(config.dashboard.publicKey, config.tenantId);
  const bundles = new BundleManager({
    tenantId: config.tenantId,
    apiBaseUrl: config.dashboard.url,
    deploymentKey: config.dashboard.apiKey,
    cacheFile: config.dashboard.cacheFile,
  }, verifier);
  const bundle = await bundles.start();
  const snapshot = new PolicySnapshot(bundle);
  const redis = new RedisStorage({ url: config.redisUrl });
  await connectOptional(() => redis.connect());
  const tenantRedis = redis.tenant(config.tenantId).sub(bundle.version);
  const credential = new CredentialManager(
    config.dashboard.url,
    config.dashboard.apiKey,
    (credentialVersion) => tenantRedis.sub(`jev-${credentialVersion}`),
  );
  await credential.refresh();
  const decision = bundle.runtimeConfig.decision;
  const runtime: RuntimeConfig = {
    sampling: { probabilityN: bundle.runtimeConfig.samplingRate, minN: decision.sampling.minN, maxN: decision.sampling.maxN },
    threshold: {
      attackProbabilityThreshold: decision.jev.attackProbabilityThreshold,
      attackProbabilityFloor: decision.jev.attackProbabilityFloor,
      locked: decision.jev.locked,
    },
  };
  const failures: DecisionConfig = {
    staticAnalysisError: decision.onStaticAnalysisError.toUpperCase() as DecisionConfig["staticAnalysisError"],
    suspiciousWhenJevUnavailable: decision.onSuspiciousJevUnavailable.toUpperCase() as DecisionConfig["suspiciousWhenJevUnavailable"],
    sampledWhenJevUnavailable: decision.onSampledJevUnavailable.toUpperCase() as DecisionConfig["sampledWhenJevUnavailable"],
  };
  const orchestrator = new DecisionOrchestrator({
    jev: credential,
    adaptive: new AdaptiveControl(),
    sampler: new Sampler(),
    configFor: () => runtime,
  }, failures);
  const reporter = new ProxyReporter({
    tenantId: config.tenantId,
    apiBaseUrl: config.dashboard.url,
    deploymentKey: config.dashboard.apiKey,
    proxyVersion: version,
  }, bundles);
  const ingress = new IngressServer({
    normalizer: new Normalizer(),
    runner: new Runner(),
    aggregator: new Aggregator(),
    orchestrator,
    snapshot,
    reporter,
  }, { tenantId: config.tenantId, port: config.ingress.port });
  await ingress.start();
  reporter.start();
  const credentialTimer = setInterval(() => { void credential.refresh(); }, 60_000);
  credentialTimer.unref();

  const shutdown = async (): Promise<void> => {
    clearInterval(credentialTimer);
    await ingress.stop();
    await reporter.stop();
    await redis.disconnect();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("[bootstrap] failed to start:", error);
  process.exit(1);
});
