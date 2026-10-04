import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, normalizeIp, safe, suspicious } from '@tessera/core/static-analysis/shared';

export default class TorExitNode extends Tool<ToolContextType.Full> {
    // the real exit list has a few thousand entries and is refreshed hourly, so lookups go through a Set
    private readonly exitNodes: ReadonlySet<string>;

    constructor(config: ToolConfig<'tor_exit_node'>) {
        super({
            id: 'tor_exit_node',
            displayName: 'Tor exit node',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
        this.exitNodes = new Set(config.exitNodes);
    }

    override run(context: NormalizedRequest): ToolResult {
        const ip = normalizeIp(context.clientIp);
        // suspicious, not blocked: Tor is also used by people who simply need privacy
        return this.exitNodes.has(ip) ? suspicious(this.tool, { clientIp: ip, reason: 'tor_exit_node' }) : safe(this.tool);
    }
}
