import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, metadataOf, methodOf, pathOf, routeTemplate, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class ResponseSizeAnomaly extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) METHOD route template -> recent response sizes.
    private readonly sizes: SlidingWindow<number>;

    constructor(private readonly config: ToolConfig<'response_size_anomaly'>, state: ToolState) {
        super({
            id: 'response_size_anomaly',
            displayName: 'Response size anomaly',
            category: ToolCategory.DataLeakage,
            contextType: ToolContextType.Full,
        });
        this.sizes = state.window<number>('sizes', config.baselineWindowMs, config.maxSamples);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        // only meaningful on the response pass; before the upstream answers there is nothing to measure
        const response = metadataOf(context).response;
        const size = typeof response?.size === 'number' ? response.size : typeof response?.body === 'string' ? Buffer.byteLength(response.body) : undefined;
        if (size === undefined) {
            return safe(this.tool);
        }

        const route = `${methodOf(context)} ${routeTemplate(pathOf(context))}`;
        const key = route;
        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();

        // judge against the baseline before this response joins it
        const baseline = (await this.sizes.peek(context.tenantId, key, now)).map(event => event.value);
        await this.sizes.record(context.tenantId, key, size, now);

        const { maxResponseBytes, minSamples, minAnomalousBytes, minFactorOverMedian, minStdDeviations } = this.config;
        if (size > maxResponseBytes) {
            return violation(this.tool, { route, size, limit: maxResponseBytes });
        }
        // no baseline, no judgement; and small responses are never worth flagging
        if (baseline.length < minSamples || size < minAnomalousBytes) {
            return safe(this.tool);
        }

        const sorted = [...baseline].sort((a, b) => a - b);
        const median = sorted[Math.floor(sorted.length / 2)];
        const mean = baseline.reduce((sum, value) => sum + value, 0) / baseline.length;
        const deviation = Math.sqrt(baseline.reduce((sum, value) => sum + (value - mean) ** 2, 0) / baseline.length);

        if (size > median * minFactorOverMedian && size > mean + minStdDeviations * deviation) {
            return suspicious(this.tool, { route, size, median, mean: Math.round(mean), samples: baseline.length });
        }
        return safe(this.tool);
    }
}
