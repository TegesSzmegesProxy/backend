import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, lookupCidr, normalizeIp, parseIpv4, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class IpReputation extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'ip_reputation'>) {
        super({
            id: 'ip_reputation',
            displayName: 'IP reputation',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const ip = normalizeIp(context.clientIp);
        if (!parseIpv4(ip) && !/^[0-9a-f:]+$/.test(ip)) {
            return failure(this.tool, { clientIp: clip(context.clientIp), reason: 'invalid_address' });
        }

        // ponytail: feeds are IPv4-only (see the contract), so IPv6 clients are never listed
        const entry = lookupCidr(ip, this.config.feed);
        if (!entry) {
            return safe(this.tool);
        }

        const evidence = { clientIp: ip, score: entry.score, lists: entry.lists, network: entry.cidr };
        if (entry.score >= this.config.blockScore) return violation(this.tool, evidence);
        if (entry.score >= this.config.suspiciousScore) return suspicious(this.tool, evidence);
        return safe(this.tool);
    }
}
