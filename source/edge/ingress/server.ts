import Fastify, { type FastifyInstance } from "fastify";
import replyFrom from "@fastify/reply-from";
import type { Normalizer } from "../normalizer";
import type { ExecutionPlan, Runner } from "@tessera/core/static-analysis/runner";
import type { Aggregator } from "@tessera/core/static-analysis/aggregator";
import type { DecisionOrchestrator } from "@tessera/core/decisionOrchestrator";
import type { NormalizedRequest } from '@tessera/shared/contracts';

const REQUESTS_CACHE_TTL_SECONDS = 60 * 60;

/** Where the latest requests per client IP are kept; in production a tenant-scoped `TenantRedis` namespace. */
interface RecentRequestStore {
  pushRecent(key: string, value: string, max: number, ttlSeconds: number): Promise<void>;
}

interface IngressDependencies {
  normalizer: Normalizer;
  runner: Runner;
  aggregator: Aggregator;
  orchestrator: DecisionOrchestrator;
  /** The static-analysis plan for a request; comes from the active policy. */
  planFor(request: NormalizedRequest): ExecutionPlan;
  recentRequests: RecentRequestStore;
}

interface IngressConfig {
  tenantId: string;
  port: number;
  host?: string;
  upstreamUrl: string;
  /** How many recent requests to keep per client IP; 0 disables the cache. */
  requestsCacheSize: number;
}

class IngressServer {
  private readonly app: FastifyInstance = Fastify();

  constructor(
    private readonly deps: IngressDependencies,
    private readonly config: IngressConfig,
  ) {}

  async start(): Promise<void> {
    await this.app.register(replyFrom, { base: this.config.upstreamUrl });
    this.registerRoutes();
    await this.app.listen({ port: this.config.port, host: this.config.host ?? "0.0.0.0" });
  }

  private registerRoutes(): void {
    this.app.route({
      method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      url: "/*",
      handler: async (request, reply) => {
        const { normalizer, runner, aggregator, orchestrator, planFor } = this.deps;
        const normalized = normalizer.normalize(request, this.config.tenantId);
        this.cacheRequest(normalized);
        const staticResult = aggregator.aggregate(runner.run(normalized, planFor(normalized)));
        const decision = await orchestrator.orchestrate(normalized, staticResult);

        if (decision.action === "BLOCK") {
          return reply.code(403).send({ requestId: normalized.requestId });
        }
        return reply.from(request.raw.url ?? "/");
      },
    });
  }

  // Fire-and-forget: Redis is non-authoritative, so a failed write must not delay or fail the request.
  private cacheRequest(request: NormalizedRequest): void {
    const max = this.config.requestsCacheSize;
    if (max === 0) return;
    this.deps.recentRequests
      .pushRecent(request.clientIp, JSON.stringify(request), max, REQUESTS_CACHE_TTL_SECONDS)
      .catch((error) => console.warn("[ingress] failed to cache request:", error));
  }

  async stop(): Promise<void> {
    await this.app.close();
  }
}

export { IngressServer };
export type { IngressConfig, IngressDependencies, RecentRequestStore };
