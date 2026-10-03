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
        const requestCopy = request
        const normalized = this.normalizer.normalize(request, tenantId); 
        const toolResult =  this.runner.run(normalized, [{tool: new StringLength(), target: "test"}] )
        let staticResult = this.aggregator.aggregate(toolResult)
        //decision orchestrator
        switch(staticResult.verdict){
          case "ERROR": {
          return reply.code(500).send({requestId: requestCopy.id})
          }
          case 'SUSPICIOUS': {
            break;
          }
          case 'POLICY_VIOLATION':  {
            return reply.code(400).send({requestId: requestCopy.id})
          }
          case 'SAFE': {
            return reply.from(request.raw.url ?? "/");
          }

        }
        
        return reply.code(202).send({ requestId: normalized.requestId });
      },
        
    });
  }

  async stop(): Promise<void> {
    await this.app.close();
    await this.broker?.disconnect();
  }
}

export { IngressServer };
