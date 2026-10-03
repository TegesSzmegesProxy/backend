import { resolve } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";
import fastifyEnv from "@fastify/env";
import replyFrom from "@fastify/reply-from";
import { Broker } from "../../shared/broker";
import { Normalizer } from "../normalizer";
import { Runner } from "@tessera/core/static-analysis/runner";
import StringLength from "@tessera/core/static-analysis/tools/schema/stringLength";
import { Tool } from "@tessera/core/static-analysis/shared";
import { Aggregator } from "@tessera/core/static-analysis/aggregator";
import { JevClient } from "@tessera/core/jev/client";
import { TypeSafeClient } from "@typesafe-ai/sdk";
import { DecisionOrchestrator } from "@tessera/core/decisionOrchestrator";
import { Sampler } from "@tessera/core/sampling";
import { AdaptiveControl } from "@tessera/feedback";
import SqlInjection from "@tessera/core/static-analysis/tools/injection/sqlinjection";
import CommandInjection from "@tessera/core/static-analysis/tools/injection/commandinjection";
import Xss from "@tessera/core/static-analysis/tools/injection/xss";
type Env = {
  REDIS_URL: string;
  PORT: string;
  TENANT_ID: string;
  UPSTREAM_URL: string;
};

class IngressServer {
  private readonly app: FastifyInstance = Fastify();
  private broker: Broker | undefined;
  private runner =  new Runner()
  private aggregator = new Aggregator()
  constructor(private readonly normalizer: Normalizer = new Normalizer()) {}
  // Placeholder values until per-tenant runtime config arrives with the policy bundle (TODO T04/T20/T31/T35).
  // N is a probability (0-1); thresholds are on the JEV attack probability (0-1) and tighten toward the floor under attack.
  private orchestrator = new DecisionOrchestrator(
    {
      jev: new JevClient(new TypeSafeClient({})),
      adaptive: new AdaptiveControl(),
      sampler: new Sampler(),
      configFor: () => ({
        sampling: { probabilityN: 0.1, minN: 0.01, maxN: 1 },
        threshold: { attackProbabilityThreshold: 0.7, attackProbabilityFloor: 0.5, locked: false },
      }),
    },
    {
      staticAnalysisError: "BLOCK",
      suspiciousWhenJevUnavailable: "BLOCK",
      sampledWhenJevUnavailable: "ALLOW",
    }
  )
  async start(): Promise<void> {
    await this.app.register(fastifyEnv, {
      schema: {
        type: "object",
        required: ["REDIS_URL", "UPSTREAM_URL"],
        properties: {
          REDIS_URL: { type: "string" },
          UPSTREAM_URL: { type: "string" },
          PORT: { type: "string", default: "62197" },
          TENANT_ID: { type: "string", default: "default" },
        },
      },
      dotenv: { path: resolve(process.cwd(), "source/.env") },
    });
    const env = this.app.getEnvs<Env>();
    
    this.broker = new Broker({ url: env.REDIS_URL });
    await this.broker.connect();

    await this.app.register(replyFrom, { base: env.UPSTREAM_URL });

    this.registerRoutes(env.TENANT_ID);

    await this.app.listen({ port: Number(env.PORT), host: "0.0.0.0" });
  }

  private registerRoutes(tenantId: string): void {
    this.app.route({
      method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      url: "/*",
      handler: async (request, reply) => {
        const normalized = this.normalizer.normalize(request, tenantId); 
        const toolResult =  this.runner.run(normalized, [{tool: new Xss(), target: "login"}, {tool: new SqlInjection(), target: "login"}] )
        let staticResult = this.aggregator.aggregate(toolResult)
        const decision = await this.orchestrator.orchestrate(normalized, staticResult)

        if (decision.action === "BLOCK") {
          return reply.code(403).send({ requestId: normalized.requestId })
        }
        return reply.from(request.raw.url ?? "/")
      },
        
    });
  }

  async stop(): Promise<void> {
    await this.app.close();
    await this.broker?.disconnect();
  }
}

export { IngressServer };
