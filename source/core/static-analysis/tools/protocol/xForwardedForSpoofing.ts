import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, clip, header, inCidr, isPrivateIpv4, normalizeIp, parseIpv4, safe, suspicious,
} from '@tessera/core/static-analysis/shared';

export default class XForwardedForSpoofing extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'x_forwarded_for_spoofing'>) {
        super({
            id: 'x_forwarded_for_spoofing',
            displayName: 'X-Forwarded-For spoofing',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const xff = header(context, 'x-forwarded-for');
        // headers apps read as "the real client IP"
        const clientHeaders = this.config.clientIpHeaders.map(name => ({ name, value: header(context, name) })).filter(entry => entry.value !== undefined);
        if (xff === undefined && clientHeaders.length === 0) {
            return safe(this.tool);
        }

        const findings: { rule: string; detail?: string }[] = [];
        const fromTrustedProxy = this.config.trustedProxies.some(cidr => inCidr(context.clientIp, cidr));

        // only our own proxies may tell us who the client is; anyone else setting these is lying or confused
        if (!fromTrustedProxy) {
            if (xff !== undefined) findings.push({ rule: 'xff_from_untrusted_source' });
            for (const { name } of clientHeaders) findings.push({ rule: 'client_ip_header_from_untrusted_source', detail: name });
        }

        if (xff !== undefined) {
            const chain = xff.split(',').map(entry => entry.trim());
            if (chain.length > this.config.maxChain) {
                findings.push({ rule: 'long_chain', detail: String(chain.length) });
            }
            for (const entry of chain) {
                const ip = normalizeIp(entry);
                if (!parseIpv4(ip) && !/^[0-9a-f:]+$/.test(ip)) {
                    findings.push({ rule: 'malformed_entry', detail: clip(entry, 50) });
                } else if (parseIpv4(ip) && isPrivateIpv4(ip) && !fromTrustedProxy) {
                    // "X-Forwarded-For: 127.0.0.1" to look like an internal caller
                    findings.push({ rule: 'internal_address_claimed', detail: ip });
                }
            }
        }

        return findings.length > 0 ? suspicious(this.tool, { clientIp: context.clientIp, findings: findings.slice(0, 10) }) : safe(this.tool);
    }
}
