import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, decodeLayers, safe, suspicious, urlAuthorities } from '@tessera/core/static-analysis/shared';

// Instance-metadata endpoints. Reaching one from the server leaks cloud credentials.
const METADATA_IPS = new Set([
    '169.254.169.254', // AWS, Azure, GCP, OpenStack, DigitalOcean, Oracle (v2)
    '169.254.170.2', // AWS ECS task metadata
    '169.254.169.123', // AWS time sync, same link-local block
    '100.100.100.200', // Alibaba Cloud
    '192.0.0.192', // Oracle Cloud (v1)
    '168.63.129.16', // Azure WireServer
]);
const METADATA_IPV6 = new Set(['fd00:ec2::254', 'fd00:ec2:0:0:0:0:0:254']); // AWS IMDS over IPv6
const METADATA_HOSTS = /^(?:metadata\.google\.internal|metadata\.goog|metadata|instance-data(?:\.ec2\.internal)?|metadata\.azure\.com|metadata\.packet\.net|metadata\.platformequinix\.com)$/;
// Paths that only exist on metadata services, so they reveal the target even behind a redirector.
const METADATA_PATHS = /\/latest\/(?:meta-data|user-data|dynamic|api\/token)|\/computeMetadata\/v1|\/metadata\/(?:instance|identity|v1|scheduledevents)|\/openstack\/latest|\/opc\/v[12]\/|\/v1\/credentials\?|\/2009-04-04\/meta-data/i;

const MAX_LENGTH = 4096;

export default class CloudMetadata extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'cloud_metadata',
            displayName: 'Cloud metadata endpoint',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const rules = new Set<string>();
        for (const layer of decodeLayers(context.value.slice(0, MAX_LENGTH), 2)) {
            for (const { host } of urlAuthorities(layer)) {
                const rule = CloudMetadata.classifyHost(host);
                if (rule) rules.add(rule);
            }
            // a bare address or hostname, e.g. a "webhook host" field
            const bare = layer.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/:\d+$/, '');
            // address-like only (a dot or colon), so a plain word such as "metadata" in a tag field doesn't count
            const bareRule = /^[\w.:-]+$/.test(bare) && /[.:]/.test(bare) ? CloudMetadata.classifyHost(bare) : undefined;
            if (bareRule) rules.add(bareRule);
            if (METADATA_PATHS.test(layer)) rules.add('metadata_path');
        }

        return rules.size > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: [...rules] })
            : safe(this.tool);
    }

    private static classifyHost(rawHost: string): string | undefined {
        const host = rawHost.replace(/\.$/, '');
        if (METADATA_HOSTS.test(host)) return 'metadata_hostname';
        if (METADATA_IPV6.has(host)) return 'metadata_ipv6';

        // Canonicalize through the WHATWG parser, so 0xa9fea9fe, 2852039166, 0251.0376.0251.0376 and
        // ::ffff:a9fe:a9fe all become 169.254.169.254 before the comparison.
        let canonical = host;
        try {
            canonical = new URL(`http://${host.includes(':') ? `[${host}]` : host}/`).hostname;
        } catch {
            return undefined;
        }
        const mapped = canonical.match(/^\[::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/);
        if (mapped) {
            const high = parseInt(mapped[1], 16);
            const low = parseInt(mapped[2], 16);
            canonical = `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
        }
        if (METADATA_IPS.has(canonical)) {
            return canonical === host ? 'metadata_ip' : 'obfuscated_metadata_ip';
        }
        return undefined;
    }
}
