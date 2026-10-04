import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, clip, isPrivateIpv4, parseIpv4, safe, suspicious, urlAuthorities,
} from '@tessera/core/static-analysis/shared';

// Public services built for rebinding tests: the name resolves to a different address on every lookup,
// or encodes the two addresses it alternates between (7f000001.c0a80001.rbndr.us).
const REBINDING_SERVICES = /(?:^|\.)(?:rbndr\.us|rebind\.it|rebind\.network|1u\.ms|lock\.cmpxchg8b\.com|rebinder\.net)$/;
const ENCODED_PAIR = /^(?:[0-9a-f]{8})\.(?:[0-9a-f]{8})\./; // rbndr-style hex address pair
const MAKE_REBIND = /(?:^|\.)make-[\d-]+-rebind[\w-]*\./; // 1u.ms "make-1.2.3.4-rebind-127.0.0.1-rr"

export default class DnsRebinding extends Tool<ToolContextType.Field> {
    // host -> its known DNS answers
    private readonly knownAnswers: ReadonlyMap<string, string[]>;

    constructor(config: ToolConfig<'dns_rebinding'>) {
        super({
            id: 'dns_rebinding',
            displayName: 'DNS rebinding',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
        this.knownAnswers = new Map(config.knownAnswers.map(entry => [entry.host, entry.addresses]));
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const hosts = urlAuthorities(context.value.slice(0, 4096)).map(authority => authority.host);
        const bare = context.value.trim().toLowerCase();
        if (hosts.length === 0 && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+\.?$/.test(bare)) {
            hosts.push(bare);
        }

        const findings: { host: string; rule: string; addresses?: string[] }[] = [];
        for (const rawHost of hosts) {
            const host = rawHost.replace(/\.$/, '');
            if (parseIpv4(host)) continue; // literal addresses don't resolve; Ssrf judges them

            if (REBINDING_SERVICES.test(host) || ENCODED_PAIR.test(host) || MAKE_REBIND.test(host)) {
                findings.push({ host: clip(host, 100), rule: 'rebinding_service' });
                continue;
            }

            // ponytail: tools run synchronously, so the answer comes from configured data instead of a live lookup.
            // A real implementation resolves once here and pins that address for the outgoing request.
            const addresses = this.knownAnswers.get(host);
            if (!addresses) continue;
            const privateAnswers = addresses.filter(address => isPrivateIpv4(address));
            if (privateAnswers.length > 0 && privateAnswers.length < addresses.length) {
                // public and private answers for one name: the check sees the public one, the fetch the private one
                findings.push({ host: clip(host, 100), rule: 'mixed_public_private_answers', addresses });
            } else if (privateAnswers.length > 0) {
                findings.push({ host: clip(host, 100), rule: 'resolves_to_private_address', addresses });
            }
        }

        return findings.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, findings: findings.slice(0, 5) })
            : safe(this.tool);
    }
}
