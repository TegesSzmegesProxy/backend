import { IngressServer } from "./edge";

async function main(): Promise<void> {
  const ingress = new IngressServer();
  await ingress.start();

  const shutdown = async (): Promise<void> => {
    await ingress.stop();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("[bootstrap] failed to start:", error);
  process.exit(1);
});
