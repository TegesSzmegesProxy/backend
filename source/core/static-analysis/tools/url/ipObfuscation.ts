import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious, urlAuthorities } from '@tessera/core/static-analysis/shared';

// Ssrf already resolves these forms inside explicit URLs (the WHATWG parser rewrites 0x7f.1 to 127.0.0.1)
// and checks where they point. This tool reports the notation itself, wherever it points, and also catches
// bare values Ssrf skips. A legitimate client never writes an IP address in octal.

const MAX_LENGTH = 4096;

export default class IpObfuscation extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'ip_obfuscation',
            displayName: 'IP address obfuscation',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = context.value.slice(0, MAX_LENGTH);
        const findings: { host: string; rule: string; resolvesTo?: string }[] = [];

        for (const { host } of urlAuthorities(value)) {
            const rule = IpObfuscation.classify(host, true);
            if (rule) findings.push({ host: clip(host, 60), rule, resolvesTo: IpObfuscation.resolve(host) });
        }

        // A bare value only counts with an unambiguous marker (hex, octal, mapped IPv6): "127.1" and
        // "20230101" are far more often a version or a number than an address.
        if (findings.length === 0) {
            const bare = value.trim().replace(/^\[|\](?::\d+)?$/g, '').toLowerCase();
            const rule = IpObfuscation.classify(bare, false);
            if (rule) findings.push({ host: clip(bare, 60), rule, resolvesTo: IpObfuscation.resolve(bare) });
        }

        return findings.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, findings: findings.slice(0, 5) })
            : safe(this.tool);
    }

    private static classify(host: string, inUrl: boolean): string | undefined {
        if (host === '') return undefined;
        if (/%[0-9a-f]{2}/i.test(host) && /^[\d.%a-fx]+$/i.test(host)) return 'percent_encoded_ip';
        if (/[０-９。．｡]/.test(host) && /^[\d０-９.。．｡]+$/.test(host)) return 'unicode_digits_or_dots';

        // IPv6 forms that embed an IPv4 address
        if (/^::ffff:(?:0{1,4}:)?(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{1,4}:[0-9a-f]{1,4})$/.test(host)) return 'ipv4_mapped_ipv6';
        if (/^::\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return 'ipv4_compatible_ipv6';
        if (/^64:ff9b::/.test(host)) return 'nat64_ipv6';

        const parts = host.split('.');
        if (parts.length > 4 || !parts.every(part => /^(?:0x[0-9a-f]*|\d+)$/i.test(part))) return undefined;

        if (parts.some(part => /^0x/i.test(part))) return 'hex_ip';
        if (parts.some(part => /^0\d+$/.test(part))) return 'octal_ip';
        if (!inUrl) return undefined; // plain decimal forms are only unambiguous as a URL host
        if (parts.length === 1 && Number(parts[0]) > 255) return 'decimal_ip';
        if (parts.length > 1 && parts.length < 4) return 'shortened_ip';
        if (parts.length === 4 && parts.some(part => Number(part) > 255)) return 'overflowing_octet';
        return undefined;
    }

    // What the WHATWG URL parser (Node's fetch, browsers) turns the host into.
    private static resolve(host: string): string | undefined {
        try {
            const hostname = new URL(`http://${host.includes(':') ? `[${host}]` : host}/`).hostname;
            return hostname !== host ? hostname : undefined;
        } catch {
            return undefined;
        }
    }
}
