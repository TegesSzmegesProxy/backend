import { Transform } from "node:stream";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import replyFrom from "@fastify/reply-from";
import type { Normalizer } from "../normalizer";
import type { Runner } from "@tessera/core/static-analysis/runner";
import type { Aggregator } from "@tessera/core/static-analysis/aggregator";
import type { DecisionOrchestrator } from "@tessera/core/decisionOrchestrator";
import type { PolicySnapshot, ResolvedPolicy } from "@tessera/core/policy/PolicySnapshot";
import type { ProxyReporter } from "@tessera/shared/telemetry/ProxyReporter";

/** The running policy; a fetched one can replace it between requests. Implemented by `ActivePolicy`. */
interface PolicyProvider {
  readonly snapshot: PolicySnapshot;
}

interface IngressDependencies {
  normalizer: Normalizer;
  runner: Runner;
  aggregator: Aggregator;
  orchestrator: DecisionOrchestrator;
  policy: PolicyProvider;
  reporter: ProxyReporter;
}

interface IngressConfig {
  tenantId: string;
  port: number;
  host?: string;
}

/** The largest body any bundle may allow; the running policy's own limit is checked per request. */
const BODY_LIMIT_CEILING = 104_857_600;

class IngressServer {
  private readonly app: FastifyInstance;

  constructor(
    private readonly deps: IngressDependencies,
    private readonly config: IngressConfig,
  ) {
    this.app = Fastify({ bodyLimit: BODY_LIMIT_CEILING, exposeHeadRoutes: false });
  }

  async start(): Promise<string> {
    // The upstream is fixed for the server's lifetime; a fetched policy that changes it requires a restart.
    await this.app.register(replyFrom, { base: this.deps.policy.snapshot.bundle.runtimeConfig.upstreamUrl });
    this.registerBodyLimit();
    this.registerRoutes();
    return this.app.listen({ port: this.config.port, host: this.config.host ?? "0.0.0.0" });
  }

  // Fastify's own bodyLimit is fixed at construction, so the running policy's limit is enforced here: by the declared
  // length before the body is read, and by counting bytes for bodies sent without one.
  private registerBodyLimit(): void {
    const limit = () => this.deps.policy.snapshot.bundle.runtimeConfig.thresholds.maxRequestBodyBytes;
    this.app.addHook("onRequest", async (request, reply) => {
      const max = limit();
      if (Number(request.headers["content-length"] ?? 0) > max || (max === 0 && request.headers["transfer-encoding"])) {
        return reply.code(413).send({ requestId: request.id });
      }
    });
    this.app.addHook("preParsing", async (_request, _reply, payload) => {
      const max = limit();
      let received = 0;
      const counter = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          received += chunk.length;
          if (received > max) callback(Object.assign(new Error("Request body is too large"), { statusCode: 413 }));
          else callback(null, chunk);
        },
      });
      payload.on("error", (error) => counter.destroy(error));
      return payload.pipe(counter);
    });
  }

  private registerRoutes(): void {
    this.app.route({
      method: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
      url: "/*",
      handler: async (request, reply) => {
        // One snapshot per request, so a policy swapped in meanwhile never mixes with this one.
        const snapshot = this.deps.policy.snapshot;
        const { normalizer, runner, aggregator, orchestrator, reporter } = this.deps;
        const rawPath = request.url.split("?")[0] ?? "/";
        const timeout = snapshot.bundle.runtimeConfig.thresholds.requestTimeoutMs;
        try {
          const normalized = normalizer.normalize(request, this.config.tenantId);
          console.log(`Normalized request ${normalized.requestId} (endpoint ${normalized.endpoint ?? "unknown"})`);
          let resolved: ResolvedPolicy | undefined = snapshot.match(request.method, rawPath);
          if (resolved) {
            normalized.endpoint = resolved.key!;
          } else {
            const action = snapshot.bundle.runtimeConfig.unknownEndpointBehavior === "block" ? "BLOCK" : "ALLOW";
            console.log(`No matching route for ${normalized.requestId} (path ${rawPath}, method ${request.method}). Applying unknown endpoint behavior: ${action}`);
            if (action === "BLOCK") {
              reporter.record(null, { action });
              return reply.code(403).send({ requestId: normalized.requestId });
            }
            // Global and environment policies apply to every request, including ones no endpoint policy lists.
            resolved = snapshot.matchUnknown(rawPath);
            // One adaptive-sampling key for all unlisted paths, so arbitrary paths cannot grow per-endpoint state.
            normalized.endpoint = `${request.method} *`;
            if (resolved.plan.length === 0) {
              reporter.record(null, { action });
              return this.forward(request, reply, resolved.upstreamPath, timeout);
            }
          }
          const staticResult = aggregator.aggregate(await runner.run(normalized, resolved.plan));
          console.log(`Static analysis result for ${normalized.requestId} (endpoint ${normalized.endpoint}):`, staticResult);
          const decision = await orchestrator.orchestrate(normalized, staticResult, resolved.context);
          reporter.record(resolved.key, decision);

          if (decision.action === "BLOCK") {
            return reply.code(403).send({ requestId: normalized.requestId });
          }
          return this.forward(request, reply, resolved.upstreamPath, timeout);
        } catch {
          const action = snapshot.bundle.runtimeConfig.failureBehavior === "block" ? "BLOCK" : "ALLOW";
          reporter.record(null, { action }, true);
          if (action === "BLOCK") return reply.code(403).send({ requestId: request.id });
          return this.forward(request, reply, snapshot.routePath(rawPath) ?? rawPath, timeout);
        }
      },
    });
  }

  private forward(request: FastifyRequest, reply: FastifyReply, upstreamPath: string, timeout: number) {
    const query = request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : "";
    return reply.from(`${upstreamPath}${query}`, { timeout });
  }

  async stop(): Promise<void> {
    await this.app.close();
  }
}

export { IngressServer };
export type { IngressConfig, IngressDependencies, PolicyProvider };
