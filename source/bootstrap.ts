import { IngressServer } from "./edge";

const ingress = new IngressServer();
await ingress.start();

const shutdown = async (): Promise<void> => {
  await ingress.stop();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
