import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class RateLimit extends Tool<ToolContextType.Full> {
    // hard-coded until we have enough infrastructure to support tool configuration
    private static readonly LIMIT = 100; // requests allowed per window
    private static readonly WINDOW_MS = 60_000;

    // Sliding-window log: key -> timestamps of the most recent hits (oldest first).
    // Per instance: the plan must reuse one instance across requests.
    private readonly hits = new Map<string, number[]>();
    private lastSweep = 0;

    constructor() {
        super({
            id: 'rate_limit',
            displayName: 'Rate limit',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const { LIMIT, WINDOW_MS } = RateLimit;
        const now = Date.now();
        const key = `${context.tenantId}|${context.clientIp}|${context.endpoint}`;

        this.sweep(now);

        // drop hits that have left the window, then record this one
        const recent = (this.hits.get(key) ?? []).filter(timestamp => timestamp > now - WINDOW_MS);
        recent.push(now);

        // Only the newest LIMIT + 1 hits can matter: the request is over the limit exactly when
        // the (LIMIT + 1)th most recent hit is still inside the window. Keeps memory bounded per key.
        if (recent.length > LIMIT + 1) {
            recent.splice(0, recent.length - (LIMIT + 1));
        }
        this.hits.set(key, recent);

        if (recent.length > LIMIT) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: {
                    tenantId: context.tenantId,
                    clientIp: context.clientIp,
                    endpoint: context.endpoint,
                    limit: LIMIT,
                    windowMs: WINDOW_MS,
                },
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    // Removes keys with no hits inside the window, at most once per window, so the map can't grow forever.
    private sweep(now: number): void {
        if (now - this.lastSweep < RateLimit.WINDOW_MS) {
            return;
        }
        this.lastSweep = now;

        for (const [key, timestamps] of this.hits) {
            if (timestamps[timestamps.length - 1] <= now - RateLimit.WINDOW_MS) {
                this.hits.delete(key);
            }
        }
    }
}