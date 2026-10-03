import { createClient } from "redis";
import { TenantRedis } from "./tenant-redis";

type RedisClient = ReturnType<typeof createClient>;

type RedisStorageOptions = {
  url: string;
};

class RedisStorage {
  // Private so nothing can bypass the tenant namespace; use `tenant()`.
  private readonly client: RedisClient;
  private connecting: Promise<unknown> | undefined;

  constructor({ url }: RedisStorageOptions) {
    // Fail fast while disconnected so callers recompute instead of hanging on a queued command.
    this.client = createClient({ url, disableOfflineQueue: true });
    // An unhandled "error" event would crash the process; node-redis reconnects by itself.
    this.client.on("error", (error) => console.error("[redis] error:", error));
  }

  /** Connects unless the client is already open; concurrent calls share one attempt. */
  async connect(): Promise<void> {
    if (!this.client.isOpen) {
      this.connecting = this.client.connect();
    }
    await this.connecting;
  }

  /** Tenant-scoped view of Redis; every key it touches is prefixed with the tenant. */
  tenant(tenantId: string): TenantRedis {
    return new TenantRedis(this.client, tenantId);
  }

  async disconnect(): Promise<void> {
    if (this.client.isOpen) {
      await this.client.close();
    }
    this.connecting = undefined;
  }
}

export { RedisStorage };
export { TenantRedis } from "./tenant-redis";
export type { RedisClient, RedisStorageOptions };
