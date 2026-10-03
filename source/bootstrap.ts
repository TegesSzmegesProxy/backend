import { IngressServer } from "./edge";
import { Broker } from "./shared/broker";
import { MongoStorage, RedisStorage } from "./shared/storage";
import { tenantsDbName } from "./shared/config";

const REDIS_STARTUP_TIMEOUT_MS = 5_000;

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

async function main(): Promise<void> {
  // MongoDB is the durable source of truth: failing to connect aborts startup.
//   THIS IS top level database of app
  const mongo = new MongoStorage();
  const tenantsDb = new MongoStorage({dbName: tenantsDbName()})
  // await mongo.connect();    
  const redis = new RedisStorage();
  const broker = new Broker();
  await Promise.all([
    connectOptional("redis", () => redis.connect()),
    connectOptional("broker", () => broker.connect()),
  ]);

  const ingress = new IngressServer();
  await ingress.start();

  const shutdown = async (): Promise<void> => {
    await ingress.stop();
    await Promise.allSettled([broker.disconnect(), redis.disconnect(), mongo.disconnect()]);
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("[bootstrap] failed to start:", error);
  process.exit(1);
});
