import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, failure, safe, violation } from '@tessera/core/static-analysis/shared';

export default class ConcurrentConnections extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client -> request starts.
    private readonly starts: SlidingWindow<string>;

    constructor(private readonly config: ToolConfig<'concurrent_connections'>, state: ToolState) {
        super({
            id: 'concurrent_connections',
            displayName: 'Concurrent connections',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        // ponytail: tools only see a request when it starts, never when it finishes, so a request is assumed to be
        // in flight for assumedLatencyMs. Replace with a real counter once the ingress can report completions.
        this.starts = state.window<string>('starts', config.assumedLatencyMs, config.maxInFlight * 2);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!context.clientIp || !context.tenantId) {
            return failure(this.tool, { reason: 'missing_client_identity' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const recent = await this.starts.record(context.tenantId, context.clientIp, context.requestId, now);
        // the same requestId analyzed twice is one request, not two
        const inFlight = new Set(recent.map(event => event.value)).size;

        const { maxInFlight, assumedLatencyMs } = this.config;
        return inFlight > maxInFlight
            ? violation(this.tool, { inFlight, limit: maxInFlight, assumedLatencyMs })
            : safe(this.tool);
    }
}
