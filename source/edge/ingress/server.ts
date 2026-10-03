import Fastify, { type FastifyInstance } from "fastify";
import fastifyEnv from "@fastify/env";
import { Broker } from "../../shared/broker";

type Env = {
  REDIS_URL: string;
  PORT: string;
};

class IngressServer {
  private readonly app: FastifyInstance = Fastify();
  private broker: Broker | undefined;

  async start(): Promise<void> {
    await this.app.register(fastifyEnv, {
      schema: {
        type: "object",
        required: ["REDIS_URL"],
        properties: {
          REDIS_URL: { type: "string" },
          PORT: { type: "string", default: "62197" },
        },
      },
      dotenv: true,
    });
    const env = this.app.getEnvs<Env>();

    this.broker = new Broker({ url: env.REDIS_URL });
    await this.broker.connect();

    await this.app.listen({ port: Number(env.PORT), host: "0.0.0.0" });
  }

  async stop(): Promise<void> {
    await this.app.close();
    await this.broker?.disconnect();
  }
}

export { IngressServer };
