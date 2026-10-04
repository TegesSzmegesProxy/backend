import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, failure, findField, inRouteFilter, isStateChanging, methodOf, pathOf,
    safe, suspicious,
} from '@tessera/core/static-analysis/shared';

export default class TimingAnomaly extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client -> state-changing requests, so action bursts can be measured
    private readonly actions: SlidingWindow<true>;
    // hidden field the form page fills with its render time (ms or s since epoch)
    private readonly renderTimeFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'timing_anomaly'>, state: ToolState) {
        super({
            id: 'timing_anomaly',
            displayName: 'Timing anomaly',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        // the burst check only needs the last few actions, as long as they span the whole burst
        this.actions = state.window<true>('actions', Math.max(10_000, config.fastActionsInARow * config.minActionIntervalMs), config.fastActionsInARow + 1);
        this.renderTimeFields = new Set(config.renderTimeFields);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!context.tenantId || !context.clientIp) {
            return failure(this.tool, { reason: 'missing_client_identity' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const { minFillMs, maxClockSkewMs, minActionIntervalMs, fastActionsInARow } = this.config;
        const findings: Record<string, unknown>[] = [];

        const rendered = findField(context, this.renderTimeFields);
        if (rendered && inRouteFilter(pathOf(context), this.config.formRoutes)) {
            const raw = Number(rendered.value);
            if (Number.isFinite(raw) && raw > 0) {
                const renderedAt = raw < 1e12 ? raw * 1000 : raw; // seconds or milliseconds
                const elapsed = now - renderedAt;
                if (elapsed < -maxClockSkewMs) {
                    findings.push({ rule: 'form_rendered_in_future', elapsedMs: elapsed });
                } else if (elapsed < minFillMs) {
                    findings.push({ rule: 'form_filled_too_fast', elapsedMs: Math.max(0, elapsed), minMs: minFillMs });
                }
            } else {
                findings.push({ rule: 'invalid_render_time' });
            }
        }

        if (isStateChanging(methodOf(context))) {
            const recent = await this.actions.record(context.tenantId, context.clientIp, true, now);
            const lastActions = recent.slice(-fastActionsInARow);
            const allFast = lastActions.length === fastActionsInARow
                && lastActions.every((event, index) => index === 0 || event.at - lastActions[index - 1].at < minActionIntervalMs);
            if (allFast) {
                findings.push({ rule: 'action_sequence_too_fast', actions: fastActionsInARow, maxIntervalMs: minActionIntervalMs });
            }
        }

        return findings.length > 0 ? suspicious(this.tool, { findings }) : safe(this.tool);
    }
}
