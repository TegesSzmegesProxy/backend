import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState } from '@tessera/core/static-analysis/shared';

export default class RateLimit extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client|endpoint -> the most recent hits. Only the newest limit + 1 hits can matter: the
    // request is over the limit exactly when the (limit + 1)th most recent hit is still inside the window.
    private readonly hits: SlidingWindow<true>;

    constructor(private readonly config: ToolConfig<'rate_limit'>, state: ToolState) {
        super({
            id: 'rate_limit',
            displayName: 'Rate limit',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.hits = state.window<true>('hits', config.windowMs, config.limit + 1);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const { limit, windowMs } = this.config;
        const now = Date.now();
        const recent = await this.hits.record(context.tenantId, `${context.clientIp}|${context.endpoint}`, true, now);

        if (recent.length > limit) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: {
                    tenantId: context.tenantId,
                    clientIp: context.clientIp,
                    endpoint: context.endpoint,
                    limit,
                    windowMs,
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
}
