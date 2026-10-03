import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface SsrfFinding {
    url: string;
    rule: string;
}

interface UrlCandidate {
    raw: string;
    explicitScheme: boolean;
}

// Schemes that have no business in a user-supplied URL and are classic SSRF pivots.
const DANGEROUS_SCHEMES = new Set([
    'file:', 'gopher:', 'dict:', 'ftp:', 'tftp:', 'ldap:', 'ldaps:', 'jar:', 'netdoc:',
]);

// Hostname suffixes that normally only resolve inside a private network.
const INTERNAL_SUFFIXES = ['.local', '.internal', '.intranet', '.lan', '.corp', '.home', '.svc'];

// Public DNS services that resolve to whatever IP is embedded in the name (e.g. 127.0.0.1.nip.io).
const WILDCARD_DNS = /(?:^|\.)(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|vcap\.me)$/;

// Explicit URLs. matchAll clones the regex, so the g flag is safe on this shared constant.
const URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi;

// Scheme-less values are only examined when they are an obvious loopback/IP literal,
// so values like "10.5" or "config.local" don't produce noise.
const BARE_PATTERN = /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])(?::\d{1,5})?(?:[/?#]\S*)?$/i;

export default class Ssrf extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'ssrf',
            displayName: 'Server-side request forgery (SSRF)',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SAFE',
                evidence: undefined,
            };
        }

        const findings: SsrfFinding[] = Ssrf.extractCandidates(context.value).flatMap(({ raw, explicitScheme }) =>
            Ssrf.analyze(raw, explicitScheme).map(rule => ({ url: raw.slice(0, 200), rule })),
        );

        if (findings.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: findings,
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    private static extractCandidates(value: string): UrlCandidate[] {
        const urls = [...value.matchAll(URL_PATTERN)].map(match => ({ raw: match[0], explicitScheme: true }));
        if (urls.length > 0) {
            return urls;
        }

        const trimmed = value.trim();
        return BARE_PATTERN.test(trimmed) ? [{ raw: trimmed, explicitScheme: false }] : [];
    }

    private static analyze(raw: string, explicitScheme: boolean): string[] {
        let url: URL;
        try {
            url = new URL(explicitScheme ? raw : `http://${raw}`);
        } catch {
            return [];
        }

        const rules: string[] = [];

        if (DANGEROUS_SCHEMES.has(url.protocol)) {
            rules.push('dangerous_scheme');
        }

        // http://trusted.example.com@169.254.169.254/ -- parser-confusion trick
        if (url.username || url.password) {
            rules.push('embedded_credentials');
        }

        const hostRule = Ssrf.classifyHost(url.hostname, explicitScheme);
        if (hostRule) {
            rules.push(hostRule);
        }

        return rules;
    }

    private static classifyHost(hostname: string, explicitScheme: boolean): string | undefined {
        const host = hostname.toLowerCase().replace(/\.$/, '');

        if (host.startsWith('[')) return Ssrf.classifyIpv6(host);

        const octets = Ssrf.parseIpv4(host);
        if (octets) return Ssrf.classifyIpv4(octets);

        if (host === 'localhost' || host.endsWith('.localhost')) return 'loopback_hostname';
        if (WILDCARD_DNS.test(host)) return 'wildcard_dns_service';
        if (INTERNAL_SUFFIXES.some(suffix => host.endsWith(suffix))) return 'internal_hostname';

        // http://redis:6379, http://db/ -- typical docker/k8s service names
        if (explicitScheme && host !== '' && !host.includes('.')) return 'single_label_hostname';

        return undefined;
    }

    private static parseIpv4(host: string): number[] | undefined {
        const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (!match) {
            return undefined;
        }
        const octets = match.slice(1).map(Number);
        return octets.every(octet => octet <= 255) ? octets : undefined;
    }

    private static classifyIpv4([a, b, c, d]: number[]): string | undefined {
        if (a === 169 && b === 254 && c === 169 && d === 254) return 'cloud_metadata_ip';
        if (a === 100 && b === 100 && c === 100 && d === 200) return 'cloud_metadata_ip';
        if (a === 0) return 'unspecified_ip';
        if (a === 127) return 'loopback_ip';
        if (a === 10) return 'private_ip';
        if (a === 172 && b >= 16 && b <= 31) return 'private_ip';
        if (a === 192 && b === 168) return 'private_ip';
        if (a === 169 && b === 254) return 'link_local_ip';
        if (a === 100 && b >= 64 && b <= 127) return 'shared_address_space_ip';
        return undefined;
    }

    private static classifyIpv6(host: string): string | undefined {
        const address = host.slice(1, -1); // strip [ ]
        if (address === '::1') return 'loopback_ip';
        if (address === '::') return 'unspecified_ip';

        // IPv4-mapped, e.g. [::ffff:7f00:1] (the URL parser rewrites ::ffff:127.0.0.1 into this form)
        const mapped = address.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
        if (mapped) {
            const high = parseInt(mapped[1], 16);
            const low = parseInt(mapped[2], 16);
            return Ssrf.classifyIpv4([high >> 8, high & 255, low >> 8, low & 255]);
        }

        const first = parseInt(address.split(':')[0] || '0', 16);
        if ((first & 0xfe00) === 0xfc00) return 'private_ip'; // fc00::/7 unique local
        if ((first & 0xffc0) === 0xfe80) return 'link_local_ip'; // fe80::/10

        return undefined;
    }
}