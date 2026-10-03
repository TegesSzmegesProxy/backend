import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface SeenRequest {
    requestId: string;
    firstSeen: number;
    lastSeen: number;
    count: number; // distinct requests (different requestId) seen with this hash in the window
}

export default class DuplicateRequest extends Tool<ToolContextType.Full> {
    // hard-coded until we have enough infrastructure to support tool configuration
    private static readonly WINDOW_MS = 10_000;
    private static readonly MAX_ENTRIES = 100_000;

    // key -> most recent sighting. Per instance: the plan must reuse one instance across requests.
    private readonly seen = new Map<string, SeenRequest>();
    private lastSweep = 0;

    constructor () {
        super({
            id: 'duplicate_request',
            displayName: 'Duplicate request',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const { WINDOW_MS } = DuplicateRequest;

        // without a hash we can't compare requests, which is different from "not a duplicate"
        if (typeof context.requestHash !== 'string' || context.requestHash === '') {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { reason: 'missing_request_hash' },
            };
        }

        const now = Date.now();
        const key = `${context.tenantId}|${context.endpoint}|${context.requestHash}`;

        this.sweep(now);

        const previous = this.seen.get(key);
        const inWindow = previous !== undefined && now - previous.lastSeen <= WINDOW_MS;

        // Same requestId means the pipeline is analyzing the same request again (retry, re-run),
        // not the client sending it twice, so it is neither recorded nor flagged.
        if (inWindow && previous.requestId === context.requestId) {
            return DuplicateRequest.safe(this.tool);
        }

        const entry: SeenRequest = inWindow
            ? { requestId: context.requestId, firstSeen: previous.firstSeen, lastSeen: now, count: previous.count + 1 }
            : { requestId: context.requestId, firstSeen: now, lastSeen: now, count: 1 };

        // delete + set moves the key to the end of the Map, so insertion order stays "oldest sighting first"
        this.seen.delete(key);
        this.seen.set(key, entry);
        this.evictOverflow();

        if (entry.count > 1) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: {
                    requestHash: context.requestHash,
                    endpoint: context.endpoint,
                    count: entry.count,
                    firstSeenMsAgo: now - entry.firstSeen,
                    windowMs: WINDOW_MS,
                },
            };
        }

        return DuplicateRequest.safe(this.tool);
    }

    private static safe(tool: string): ToolResult {
        return {
            tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    // Removes expired entries, at most once per window, so the map can't grow forever.
    private sweep(now: number): void {
        if (now - this.lastSweep < DuplicateRequest.WINDOW_MS) {
            return;
        }
        this.lastSweep = now;

        for (const [key, entry] of this.seen) {
            if (now - entry.lastSeen > DuplicateRequest.WINDOW_MS) {
                this.seen.delete(key);
            }
        }
    }

    // Hard cap in case a flood of unique hashes arrives between sweeps; evicts the oldest sightings first.
    private evictOverflow(): void {
        while (this.seen.size > DuplicateRequest.MAX_ENTRIES) {
            const oldest = this.seen.keys().next();
            if (oldest.done) {
                return;
            }
            this.seen.delete(oldest.value);
        }
    }
}