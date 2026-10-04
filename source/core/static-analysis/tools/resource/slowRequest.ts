import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, failure, metadataOf, safe, violation } from '@tessera/core/static-analysis/shared';

export default class SlowRequest extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'slow_request'>) {
        super({
            id: 'slow_request',
            displayName: 'Slow request',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // receive timings come from the HTTP layer. Adjust the key names to whatever your normalizer writes.
        const timing = metadataOf(context).timing;
        if (!timing || typeof timing.headersMs !== 'number') {
            return failure(this.tool, { reason: 'missing_timing' });
        }

        const { maxHeadersMs, maxBodyMs, minBodyBytesPerSecond, minBodyMsForRate } = this.config;
        const reasons: string[] = [];
        // slowloris: headers trickled in one byte at a time
        if (timing.headersMs > maxHeadersMs) {
            reasons.push('slow_headers');
        }
        if (typeof timing.bodyMs === 'number') {
            if (timing.bodyMs > maxBodyMs) {
                reasons.push('slow_body');
            }
            // slow POST; short bodies have too little data for a meaningful rate
            if (timing.bodyMs >= minBodyMsForRate && typeof timing.bodyBytes === 'number') {
                const rate = timing.bodyBytes / (timing.bodyMs / 1000);
                if (rate < minBodyBytesPerSecond) reasons.push('trickling_body');
            }
        }

        return reasons.length > 0
            ? violation(this.tool, { reasons, headersMs: timing.headersMs, bodyMs: timing.bodyMs, bodyBytes: timing.bodyBytes })
            : safe(this.tool);
    }
}
