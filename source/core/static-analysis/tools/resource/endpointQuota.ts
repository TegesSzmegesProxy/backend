import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, failure, matchesRoute, pathOf, safe,
    violation,
} from '@tessera/core/static-analysis/shared';

export default class EndpointQuota extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client -> costs spent.
    private readonly spent: SlidingWindow<number>;

    constructor(private readonly config: ToolConfig<'endpoint_quota'>, state: ToolState) {
        super({
            id: 'endpoint_quota',
            displayName: 'Endpoint cost quota',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.spent = state.window<number>('spent', config.windowMs, 2000);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const path = pathOf(context);
        // the most specific configured route decides the cost; unlisted routes are free (RateLimit covers them)
        const entry = this.config.costs
            .filter(candidate => matchesRoute(path, [candidate.route]))
            .sort((a, b) => b.route.length - a.route.length)[0];
        if (!entry) {
            return safe(this.tool);
        }
        if (!context.clientIp || !context.tenantId) {
            return failure(this.tool, { reason: 'missing_client_identity' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const events = await this.spent.record(context.tenantId, context.clientIp, entry.cost, now);
        const total = events.reduce((sum, event) => sum + event.value, 0);

        const { costPerWindow, windowMs } = this.config;
        return total > costPerWindow
            ? violation(this.tool, { route: entry.route, cost: entry.cost, spent: total, budget: costPerWindow, windowMs })
            : safe(this.tool);
    }
}
