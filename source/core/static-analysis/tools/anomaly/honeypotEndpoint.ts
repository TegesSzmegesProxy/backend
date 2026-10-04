import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, inRouteFilter, pathOf, routeKey, safe, violation } from '@tessera/core/static-analysis/shared';

export default class HoneypotEndpoint extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'honeypot_endpoint'>) {
        super({
            id: 'honeypot_endpoint',
            displayName: 'Honeypot endpoint',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // decoy routes no legitimate client links to or calls, so any hit is reconnaissance
        let path = pathOf(context);
        try {
            path = decodeURIComponent(path);
        } catch {
            // keep the raw path
        }

        if (inRouteFilter(path, this.config.routes)) {
            return violation(this.tool, { route: routeKey(path).slice(0, 200), clientIp: context.clientIp });
        }
        return safe(this.tool);
    }
}
