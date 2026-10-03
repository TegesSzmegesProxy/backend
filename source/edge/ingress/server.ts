import { resolve } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";
import fastifyEnv from "@fastify/env";
import { Broker } from "../../shared/broker";
import { Normalizer } from "../normalizer";

type Env = {
  REDIS_URL: string;
  PORT: string;
  TENANT_ID: string;
};

class IngressServer {
  private readonly app: FastifyInstance = Fastify();
  private broker: Broker | undefined;

  constructor(private readonly normalizer: Normalizer = new Normalizer()) {}

  async start(): Promise<void> {
    await this.app.register(fastifyEnv, {
      schema: {
        type: "object",
        required: ["REDIS_URL"],
        properties: {
          REDIS_URL: { type: "string" },
          PORT: { type: "string", default: "62197" },
          TENANT_ID: { type: "string", default: "default" },
        },
      },
      dotenv: { path: resolve(process.cwd(), "source/.env") },
    });
    const env = this.app.getEnvs<Env>();
    
    this.broker = new Broker({ url: env.REDIS_URL });
    await this.broker.connect();

    this.registerRoutes(env.TENANT_ID);

    await this.app.listen({ port: Number(env.PORT), host: "0.0.0.0" });
  }

  private registerRoutes(tenantId: string): void {
    this.app.route({
      method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      url: "/*",
      handler: async (request, reply) => {
        const normalized = this.normalizer.normalize(request, tenantId);
        




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
