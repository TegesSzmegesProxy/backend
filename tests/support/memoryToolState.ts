import type { ToolStateStore, ToolStateStores } from '../../source/core/static-analysis/shared';

/**
 * In-memory stand-in for TenantRedis, with the same window and expiry semantics, so tests and the eval gateway
 * run stateful tools without a Redis server. Keys are namespaced per tenant exactly like Redis keys.
 */
export class MemoryToolState {
    private readonly values = new Map<string, { value: string; expiresAt: number }>();
    private readonly windows = new Map<string, { member: string; at: number }[]>();

    /** Fails every operation, the way a disconnected Redis client does. */
    down = false;

    readonly stores: ToolStateStores = (tenantId) => this.store(`tessera:${tenantId}:`);

    private store(prefix: string): ToolStateStore {
        const guard = (): void => {
            if (this.down) throw new Error('The client is closed');
        };
        return {
            sub: (name) => this.store(`${prefix}${name}:`),
            get: async (name) => {
                guard();
                const entry = this.values.get(prefix + name);
                return entry && entry.expiresAt > Date.now() ? entry.value : null;
            },
            setPx: async (name, value, ttlMs) => {
                guard();
                this.values.set(prefix + name, { value, expiresAt: Date.now() + ttlMs });
            },
            windowAdd: async (name, at, member, windowMs, maxEntries) => {
                guard();
                const entries = [...(this.windows.get(prefix + name) ?? []), { member, at }]
                    .filter(entry => entry.at >= at - windowMs)
                    .sort((a, b) => a.at - b.at)
                    .slice(-maxEntries);
                this.windows.set(prefix + name, entries);
                return entries;
            },
            windowRange: async (name, since) => {
                guard();
                return (this.windows.get(prefix + name) ?? []).filter(entry => entry.at >= since);
            },
        };
    }
}
