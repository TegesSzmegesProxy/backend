import type { RedisClient } from "./index";
import { assertTenantId } from "../tenant-id";

/**
 * Redis has no cheap per-tenant database: numbered databases are a small fixed set (16 by
 * default), cannot be created on demand and do not exist in cluster mode. Tenants are therefore
 * isolated by a key namespace, `tessera:{tenantId}:`, applied here so callers never build raw keys.
 */
class TenantRedis {
  private readonly prefix: string;

  constructor(
    private readonly client: RedisClient,
    private readonly tenantId: string,
    private readonly namespace: string = "",
  ) {
    this.prefix = `tessera:${assertTenantId(tenantId)}:${namespace}`;
  }

  /** Same tenant, keys further namespaced under `{name}:`. */
  sub(name: string): TenantRedis {
    return new TenantRedis(this.client, this.tenantId, `${this.namespace}${name}:`);
  }

  key(name: string): string {
    return `${this.prefix}${name}`;
  }

  get(name: string): Promise<string | null> {
    return this.client.get(this.key(name));
  }

  async set(name: string, value: string, ttlSeconds?: number): Promise<void> {
    await this.client.set(this.key(name), value, ttlSeconds ? { EX: ttlSeconds } : undefined);
  }

  async del(name: string): Promise<void> {
    await this.client.del(this.key(name));
  }

  /** Prepends `value` and keeps only the newest `max` entries (e.g. last 3 requests per IP). */
  async pushRecent(name: string, value: string, max: number, ttlSeconds: number): Promise<void> {
    const key = this.key(name);
    await this.client.multi().lPush(key, value).lTrim(key, 0, max - 1).expire(key, ttlSeconds).exec();
  }

  recent(name: string): Promise<string[]> {
    return this.client.lRange(this.key(name), 0, -1);
  }
}

export { TenantRedis };
