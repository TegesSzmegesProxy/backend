import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, inRouteFilter, pathOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

export default class RefererAnomaly extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'referer_anomaly'>) {
        super({
            id: 'referer_anomaly',
            displayName: 'Referer anomaly',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // only routes our own pages call, where a browser always sends at least one of the two
        if (!inRouteFilter(pathOf(context), this.config.routes)) {
            return safe(this.tool);
        }

        const origin = header(context, 'origin');
        const referer = header(context, 'referer');

        if (origin === undefined && referer === undefined) {
            return suspicious(this.tool, { reason: 'missing_origin_and_referer' });
        }

        const findings: { header: string; value: string; reason: string }[] = [];
        if (origin !== undefined && !this.isAllowed(origin)) {
            findings.push({ header: 'origin', value: clip(origin), reason: origin === 'null' ? 'opaque_origin' : 'foreign_origin' });
        }
        if (referer !== undefined && !this.isAllowed(referer)) {
            findings.push({ header: 'referer', value: clip(referer), reason: 'foreign_referer' });
        }

        return findings.length > 0 ? suspicious(this.tool, { findings }) : safe(this.tool);
    }

    private isAllowed(value: string): boolean {
        try {
            return this.config.allowedOrigins.includes(new URL(value).origin);
        } catch {
            return false; // "null" and garbage are not our origin
        }
    }
}
