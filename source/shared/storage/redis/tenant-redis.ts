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

  /** Sets and deletes keys in one MULTI, so readers never see part of the change. */
  async transaction(sets: [name: string, value: string][], deletes: string[] = []): Promise<void> {
    const multi = this.client.multi();
    for (const [name, value] of sets) multi.set(this.key(name), value);
    for (const name of deletes) multi.del(this.key(name));
    await multi.exec();
  }

  async publish(channel: string, message: string): Promise<void> {
    await this.client.publish(this.key(channel), message);
  }

  /**
   * Listens on `channel` over a dedicated connection (a subscribed connection can run no other commands). Messages
   * published while disconnected are lost, so callers keep a polling fallback. Returns a function that closes it.
   */
  async subscribe(channel: string, listener: (message: string) => void): Promise<() => Promise<void>> {
    const subscriber = this.client.duplicate();
    subscriber.on("error", (error) => console.error("[redis] subscriber error:", error));
    await subscriber.connect();
    await subscriber.subscribe(this.key(channel), listener);
    return async () => { if (subscriber.isOpen) await subscriber.close(); };
  }

  /** Prepends `value` and keeps only the newest `max` entries (e.g. last 3 requests per IP). */
  async pushRecent(name: string, value: string, max: number, ttlSeconds: number): Promise<void> {
    const key = this.key(name);
    await this.client.multi().lPush(key, value).lTrim(key, 0, max - 1).expire(key, ttlSeconds).exec();
  }

  recent(name: string): Promise<string[]> {
    return this.client.lRange(this.key(name), 0, -1);
  }

  /** Like `set`, with a time-to-live in milliseconds. */
  async setPx(name: string, value: string, ttlMs: number): Promise<void> {
    await this.client.set(this.key(name), value, { PX: ttlMs });
  }

  /**
   * Adds `member` at time `at` to a sorted-set sliding window, drops entries older than `windowMs` and all but the
   * newest `maxEntries`, and returns what is left (oldest first). One MULTI, so concurrent proxies see a consistent window.
   */
  async windowAdd(name: string, at: number, member: string, windowMs: number, maxEntries: number): Promise<{ member: string; at: number }[]> {
    const key = this.key(name);
    const replies = await this.client.multi()
      .zAdd(key, { score: at, value: member })
      .zRemRangeByScore(key, "-inf", `(${at - windowMs}`)
      .zRemRangeByRank(key, 0, -(maxEntries + 1))
      .pExpire(key, windowMs)
      .zRangeWithScores(key, 0, -1)
      .exec();
    return (replies[4] as unknown as { value: string; score: number }[]).map(({ value, score }) => ({ member: value, at: score }));
  }

  /** Sliding-window entries at or after `since`, oldest first, without changing the window. */
  async windowRange(name: string, since: number): Promise<{ member: string; at: number }[]> {
    const entries = await this.client.zRangeByScoreWithScores(this.key(name), since, "+inf");
    return entries.map(({ value, score }) => ({ member: value, at: score }));
  }
}

export { TenantRedis };
