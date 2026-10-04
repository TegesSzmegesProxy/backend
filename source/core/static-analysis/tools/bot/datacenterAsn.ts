import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, lookupCidr, matchesRoute, normalizeIp, pathOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

export default class DatacenterAsn extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'datacenter_asn'>) {
        super({
            id: 'datacenter_asn',
            displayName: 'Datacenter ASN',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // routes servers are expected to call (webhooks, metrics scrapers), so hosting traffic is normal there
        if (matchesRoute(pathOf(context), this.config.serverToServerRoutes)) {
            return safe(this.tool);
        }

        const ip = normalizeIp(context.clientIp);
        const entry = lookupCidr(ip, this.config.asnTable);
        // people browse from homes and phones, bots run in clouds; VPN users are the honest exception
        return entry?.hosting
            ? suspicious(this.tool, { clientIp: ip, asn: entry.asn, org: entry.org })
            : safe(this.tool);
    }
}
