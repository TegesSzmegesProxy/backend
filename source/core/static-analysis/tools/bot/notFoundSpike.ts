import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, metadataOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class NotFoundSpike extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client -> response statuses.
    private readonly statuses: SlidingWindow<number>;
    private readonly errorStatuses: ReadonlySet<number>;

    constructor(private readonly config: ToolConfig<'not_found_spike'>, state: ToolState) {
        super({
            id: 'not_found_spike',
            displayName: '404/403 spike',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
        this.statuses = state.window<number>('statuses', config.windowMs, config.errors.block * 4 + 4);
        this.errorStatuses = new Set(config.errorStatuses);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const key = context.clientIp;
        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();

        // Statuses are only known on the response pass (metadata.response). On the request pass the tool
        // judges the client by the responses it already got, so its next probe is caught before it runs.
        const status = metadataOf(context).response?.status;
        const recent = typeof status === 'number'
            ? await this.statuses.record(context.tenantId, key, status, now)
            : await this.statuses.peek(context.tenantId, key, now);
        if (recent.length === 0) {
            return safe(this.tool);
        }

        const errors = recent.filter(event => this.errorStatuses.has(event.value)).length;
        // a busy client with a few broken links is not enumerating
        const { windowMs, minErrorRatio, errors: limits } = this.config;
        const ratio = errors / recent.length;
        const evidence = { errors, responses: recent.length, ratio: Math.round(ratio * 100) / 100, windowMs };

        if (errors > limits.block && ratio >= minErrorRatio) return violation(this.tool, { ...evidence, limit: limits.block });
        if (errors > limits.suspicious && ratio >= minErrorRatio) return suspicious(this.tool, { ...evidence, threshold: limits.suspicious });
        return safe(this.tool);
    }
}
