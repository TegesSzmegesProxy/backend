import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { ExpiringMap, Tool, ToolCategory, ToolContextType, ToolResult, ToolState } from '@tessera/core/static-analysis/shared';

interface SeenRequest {
    requestId: string;
    firstSeen: number;
    lastSeen: number;
    count: number; // distinct requests (different requestId) seen with this hash in the window
}

export default class DuplicateRequest extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) endpoint|hash -> most recent sighting; it expires windowMs after the last one.
    private readonly seen: ExpiringMap<SeenRequest>;

    constructor (private readonly config: ToolConfig<'duplicate_request'>, state: ToolState) {
        super({
            id: 'duplicate_request',
            displayName: 'Duplicate request',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        this.seen = state.expiring<SeenRequest>('seen', config.windowMs);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const { windowMs } = this.config;

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
        const key = `${context.endpoint}|${context.requestHash}`;

        const previous = await this.seen.get(context.tenantId, key);
        const inWindow = previous !== undefined && now - previous.lastSeen <= windowMs;

        // Same requestId means the pipeline is analyzing the same request again (retry, re-run),
        // not the client sending it twice, so it is neither recorded nor flagged.
        if (inWindow && previous.requestId === context.requestId) {
            return DuplicateRequest.safe(this.tool);
        }

        const entry: SeenRequest = inWindow
            ? { requestId: context.requestId, firstSeen: previous.firstSeen, lastSeen: now, count: previous.count + 1 }
            : { requestId: context.requestId, firstSeen: now, lastSeen: now, count: 1 };

        await this.seen.set(context.tenantId, key, entry);

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
                    windowMs,
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
}
