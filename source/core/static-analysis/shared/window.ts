import { randomUUID } from 'node:crypto';
import { hashOf } from './request';

// Cross-request state for tools that look across requests, kept in Redis so it survives restarts and is shared by
// every proxy process of the tenant. Keys are always tenant-scoped (`tessera:{tenantId}:...`) and namespaced per
// policy step, so neither tenants nor two steps of the same tool ever see each other's state. Every operation
// can reject (Redis down or slow); the Runner turns that into an ERROR result, never into SAFE.

/** The Redis operations tool state needs, scoped to one tenant. TenantRedis implements it. */
export interface ToolStateStore {
    sub(name: string): ToolStateStore;
    get(name: string): Promise<string | null>;
    setPx(name: string, value: string, ttlMs: number): Promise<void>;
    windowAdd(name: string, at: number, member: string, windowMs: number, maxEntries: number): Promise<{ member: string; at: number }[]>;
    windowRange(name: string, since: number): Promise<{ member: string; at: number }[]>;
}

/** Tenant id -> that tenant's store (RedisStorage.tenant). */
export type ToolStateStores = (tenantId: string) => ToolStateStore;

export interface WindowEvent<T> {
    at: number;
    value: T;
}

/** Where one tool instance keeps its state: the tenant stores plus a namespace unique to its policy step. */
export class ToolState {
    constructor (
        private readonly stores: ToolStateStores,
        private readonly namespace: string,
    ) {}

    /** Sliding-window log of events per key. */
    window<T>(name: string, windowMs: number, maxPerKey = 1000): SlidingWindow<T> {
        return new SlidingWindow<T>(tenantId => this.store(tenantId, name), windowMs, maxPerKey);
    }

    /** Key -> value with a time-to-live. */
    expiring<V>(name: string, ttlMs: number): ExpiringMap<V> {
        return new ExpiringMap<V>(tenantId => this.store(tenantId, name), ttlMs);
    }

    private store(tenantId: string, name: string): ToolStateStore {
        return this.stores(tenantId).sub(`tools:${this.namespace}:${name}`);
    }
}

/** Sliding-window log of events per key, bounded per key; Redis expires idle keys. */
export class SlidingWindow<T> {
    constructor (
        private readonly store: (tenantId: string) => ToolStateStore,
        private readonly windowMs: number,
        private readonly maxPerKey = 1000,
    ) {}

    /** Records an event and returns every event for the key still inside the window, including this one. */
    async record(tenantId: string, key: string, value: T, now: number): Promise<WindowEvent<T>[]> {
        // a random id keeps two identical events at the same millisecond apart in the sorted set
        const member = JSON.stringify([randomUUID(), value]);
        const entries = await this.store(tenantId).windowAdd(hashOf(key), now, member, this.windowMs, this.maxPerKey);
        return entries.map(SlidingWindow.event<T>);
    }

    /** Events for the key inside the window, without recording anything. */
    async peek(tenantId: string, key: string, now: number): Promise<WindowEvent<T>[]> {
        const entries = await this.store(tenantId).windowRange(hashOf(key), now - this.windowMs);
        return entries.map(SlidingWindow.event<T>);
    }

    private static event<T>(entry: { member: string; at: number }): WindowEvent<T> {
        return { at: entry.at, value: (JSON.parse(entry.member) as [string, T])[1] };
    }
}

/** Key -> value with a time-to-live. */
export class ExpiringMap<V> {
    constructor (
        private readonly store: (tenantId: string) => ToolStateStore,
        private readonly ttlMs: number,
    ) {}

    async get(tenantId: string, key: string): Promise<V | undefined> {
        const raw = await this.store(tenantId).get(hashOf(key));
        return raw === null ? undefined : (JSON.parse(raw) as V);
    }

    async set(tenantId: string, key: string, value: V): Promise<void> {
        await this.store(tenantId).setPx(hashOf(key), JSON.stringify(value), this.ttlMs);
    }
}

export function distinct<T, K>(events: WindowEvent<T>[], select: (value: T) => K): Set<K> {
    return new Set(events.map(event => select(event.value)));
}
