import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class PrivateIp extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'private_ip',
            displayName: 'Private IP',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const clientIp = PrivateIp.stripPortAndBrackets(context.clientIp);

        const octets = PrivateIp.parseIpv4(clientIp);
        const groups = octets ? undefined : PrivateIp.parseIpv6(clientIp);

        if (!octets && !groups) {
            // can't evaluate, which is different from "safe"
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { clientIp: String(context.clientIp).slice(0, 100), reason: 'invalid_address' },
            };
        }

        const rule = octets ? PrivateIp.classifyIpv4(octets) : PrivateIp.classifyIpv6(groups!);

        if (rule) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: { clientIp, rule },
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    // "1.2.3.4:8080" -> "1.2.3.4", "[::1]:80" -> "::1", "fe80::1%eth0" -> "fe80::1"
    private static stripPortAndBrackets(value: unknown): string {
        let ip = typeof value === 'string' ? value.trim() : '';

        const bracketed = ip.match(/^\[([^\]]+)\](?::\d{1,5})?$/);
        if (bracketed) {
            ip = bracketed[1];
        } else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(ip)) {
            ip = ip.slice(0, ip.lastIndexOf(':'));
        }

        return ip.split('%')[0].toLowerCase();
    }

    private static parseIpv4(address: string): number[] | undefined {
        const match = address.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (!match) {
            return undefined;
        }
        const octets = match.slice(1).map(Number);
        return octets.every(octet => octet <= 255) ? octets : undefined;
    }

    // Returns the eight 16-bit groups, or undefined if the address is not valid IPv6.
    private static parseIpv6(address: string): number[] | undefined {
        if (!address.includes(':')) {
            return undefined;
        }

        // Embedded IPv4 tail, e.g. ::ffff:10.0.0.1 -> ::ffff:a00:1
        let text = address;
        const lastColon = text.lastIndexOf(':');
        if (text.slice(lastColon + 1).includes('.')) {
            const tail = PrivateIp.parseIpv4(text.slice(lastColon + 1));
            if (!tail) {
                return undefined;
            }
            const high = ((tail[0] << 8) | tail[1]).toString(16);
            const low = ((tail[2] << 8) | tail[3]).toString(16);
            text = `${text.slice(0, lastColon + 1)}${high}:${low}`;
        }

        const halves = text.split('::');
        if (halves.length > 2) {
            return undefined;
        }

        const head = halves[0] ? halves[0].split(':') : [];
        const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
        const parts = [...head, ...tail];

        if (!parts.every(part => /^[0-9a-f]{1,4}$/.test(part))) {
            return undefined;
        }

        if (halves.length === 1) {
            return parts.length === 8 ? parts.map(part => parseInt(part, 16)) : undefined;
        }

        if (parts.length > 7) {
            return undefined;
        }

        const zeros = new Array<string>(8 - parts.length).fill('0');
        return [...head, ...zeros, ...tail].map(part => parseInt(part, 16));
    }

    private static classifyIpv4([a, b]: number[]): string | undefined {
        if (a === 0) return 'unspecified_ip';
        if (a === 127) return 'loopback_ip';
        if (a === 10) return 'private_ip';
        if (a === 172 && b >= 16 && b <= 31) return 'private_ip';
        if (a === 192 && b === 168) return 'private_ip';
        if (a === 169 && b === 254) return 'link_local_ip';
        if (a === 100 && b >= 64 && b <= 127) return 'shared_address_space_ip';
        if (a === 198 && (b === 18 || b === 19)) return 'benchmarking_ip';
        return undefined;
    }

    private static classifyIpv6(groups: number[]): string | undefined {
        const leadingZeros = groups.slice(0, 5).every(group => group === 0);

        if (leadingZeros && groups[5] === 0 && groups[6] === 0) {
            if (groups[7] === 0) return 'unspecified_ip';
            if (groups[7] === 1) return 'loopback_ip';
        }

        // IPv4-mapped (::ffff:a.b.c.d) -- classify the embedded IPv4 address
        if (leadingZeros && groups[5] === 0xffff) {
            return PrivateIp.classifyIpv4([groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255]);
        }

        // NAT64 (64:ff9b::a.b.c.d)
        if (groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every(group => group === 0)) {
            return PrivateIp.classifyIpv4([groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255]);
        }

        if ((groups[0] & 0xfe00) === 0xfc00) return 'private_ip'; // fc00::/7 unique local
        if ((groups[0] & 0xffc0) === 0xfe80) return 'link_local_ip'; // fe80::/10
        if ((groups[0] & 0xffc0) === 0xfec0) return 'private_ip'; // fec0::/10 deprecated site-local

        return undefined;
    }
}