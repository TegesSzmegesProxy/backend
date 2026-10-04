import Fastify, { type FastifyInstance } from "fastify";
import replyFrom from "@fastify/reply-from";
import type { Normalizer } from "../normalizer";
import type { Runner } from "@tessera/core/static-analysis/runner";
import type { Aggregator } from "@tessera/core/static-analysis/aggregator";
import type { DecisionOrchestrator } from "@tessera/core/decisionOrchestrator";
import type { PolicySnapshot } from "@tessera/core/policy/PolicySnapshot";
import type { ProxyReporter } from "@tessera/shared/telemetry/ProxyReporter";

interface IngressDependencies {
  normalizer: Normalizer;
  runner: Runner;
  aggregator: Aggregator;
  orchestrator: DecisionOrchestrator;
  snapshot: PolicySnapshot;
  reporter: ProxyReporter;
}

interface IngressConfig {
  tenantId: string;
  port: number;
  host?: string;
}

class IngressServer {
  private readonly app: FastifyInstance;

  constructor(
    private readonly deps: IngressDependencies,
    private readonly config: IngressConfig,
  ) {
    this.app = Fastify({
      bodyLimit: Math.max(1, deps.snapshot.bundle.runtimeConfig.thresholds.maxRequestBodyBytes),
      exposeHeadRoutes: false,
    });
  }

  async start(): Promise<string> {
    await this.app.register(replyFrom, { base: this.deps.snapshot.bundle.runtimeConfig.upstreamUrl });
    this.registerRoutes();
    return this.app.listen({ port: this.config.port, host: this.config.host ?? "0.0.0.0" });
  }

  private registerRoutes(): void {
    this.app.route({
      method: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
      url: "/*",
      handler: async (request, reply) => {
        const { normalizer, runner, aggregator, orchestrator, snapshot, reporter } = this.deps;
        if (snapshot.bundle.runtimeConfig.thresholds.maxRequestBodyBytes === 0 &&
          (Number(request.headers["content-length"] ?? 0) > 0 || request.headers["transfer-encoding"])) {
          return reply.code(413).send({ requestId: request.id });
        }
        try {
          const normalized = normalizer.normalize(request, this.config.tenantId);
          console.log(`Normalized request ${normalized.requestId} (endpoint ${normalized.endpoint ?? "unknown"})`);
          const rawPath = request.url.split("?")[0] ?? "/";
          const route = snapshot.match(request.method, rawPath);
          if (!route) {
            const action = snapshot.bundle.runtimeConfig.unknownEndpointBehavior === "block" ? "BLOCK" : "ALLOW";
            console.log(`No matching route for ${normalized.requestId} (path ${rawPath}, method ${request.method}). Applying unknown endpoint behavior: ${action}`);
            reporter.record(null, { action });
            if (action === "BLOCK") return reply.code(403).send({ requestId: normalized.requestId });
            const query = request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : "";
            return reply.from(`${snapshot.routePath(rawPath) ?? rawPath}${query}`, { timeout: snapshot.bundle.runtimeConfig.thresholds.requestTimeoutMs });
          }
          normalized.endpoint = route.key;
          const staticResult = aggregator.aggregate(runner.run(normalized, route.plan));
          console.log(`Static analysis result for ${normalized.requestId} (endpoint ${normalized.endpoint}):`, staticResult);
          const decision = await orchestrator.orchestrate(normalized, staticResult);
          reporter.record(route.key, decision);

          if (decision.action === "BLOCK") {
            return reply.code(403).send({ requestId: normalized.requestId });
          }
          const query = request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : "";
          return reply.from(`${route.upstreamPath}${query}`, { timeout: snapshot.bundle.runtimeConfig.thresholds.requestTimeoutMs });
        } catch {
          const action = snapshot.bundle.runtimeConfig.failureBehavior === "block" ? "BLOCK" : "ALLOW";
          reporter.record(null, { action }, true);
          if (action === "BLOCK") return reply.code(403).send({ requestId: request.id });
          const rawPath = request.url.split("?")[0] ?? "/";
          const query = request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : "";
          return reply.from(`${snapshot.routePath(rawPath) ?? rawPath}${query}`, { timeout: snapshot.bundle.runtimeConfig.thresholds.requestTimeoutMs });
        }
      },
    });
  }

  async stop(): Promise<void> {
    await this.app.close();
  }
}

export { IngressServer };
export type { IngressConfig, IngressDependencies };
