import { NormalizedRequest } from '@tessera/shared/contracts/Request';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class CookieAbuse extends Tool<ToolContextType.Full> {
    // hard-coded until we have enough infrastructure to support tool configuration
    private static readonly MAX_HEADER_BYTES = 4096;
    private static readonly MAX_COOKIE_COUNT = 50;
    private static readonly MAX_COOKIE_VALUE_BYTES = 4096;

    // RFC 6265 cookie-name is an RFC 2616 token
    private static readonly TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
    // control characters other than horizontal tab (CR, LF, NUL, etc.)
    private static readonly CONTROL_CHARS = /[\x00-\x08\x0A-\x1F\x7F]/;

    constructor() {
        super({
            id: 'cookie_abuse',
            displayName: 'Cookie abuse',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const header = this.getCookieHeader(context.headers);

        if (header === undefined || header.trim() === '') {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SAFE',
                evidence: undefined,
            };
        }

        const violations: string[] = [];
        const suspicious: string[] = [];

        const headerBytes = Buffer.byteLength(header, 'utf8');
        if (headerBytes > CookieAbuse.MAX_HEADER_BYTES) {
            violations.push(`cookie header size ${headerBytes} > ${CookieAbuse.MAX_HEADER_BYTES}`);
        }

        if (CookieAbuse.CONTROL_CHARS.test(header)) {
            suspicious.push('control characters in cookie header');
        }

        const pairs = header.split(';').map(p => p.trim()).filter(p => p.length > 0);

        if (pairs.length > CookieAbuse.MAX_COOKIE_COUNT) {
            violations.push(`cookie count ${pairs.length} > ${CookieAbuse.MAX_COOKIE_COUNT}`);
        }

        const seen = new Set<string>();
        const duplicated = new Set<string>();

        for (const pair of pairs) {
            const separator = pair.indexOf('=');

            if (separator <= 0) {
                suspicious.push(separator === 0 ? 'cookie with empty name' : 'cookie pair without "="');
                continue;
            }

            const name = pair.slice(0, separator).trim();
            const value = pair.slice(separator + 1);

            if (!CookieAbuse.TOKEN.test(name)) {
                // name is attacker-controlled, so cap what we echo back
                suspicious.push(`invalid cookie name "${name.slice(0, 64)}"`);
                continue;
            }

            if (seen.has(name)) {
                duplicated.add(name);
            }
            seen.add(name);

            const valueBytes = Buffer.byteLength(value, 'utf8');
            if (valueBytes > CookieAbuse.MAX_COOKIE_VALUE_BYTES) {
                violations.push(`cookie "${name}" value size ${valueBytes} > ${CookieAbuse.MAX_COOKIE_VALUE_BYTES}`);
            }
        }

        // duplicate names are the signature of cookie tossing / shadowing
        for (const name of duplicated) {
            suspicious.push(`duplicate cookie name "${name}"`);
        }

        if (violations.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: [...violations, ...suspicious],
            };
        }

        if (suspicious.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: suspicious,
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    /** Header names are case-insensitive, and normalization may not have lowercased them. */
    private getCookieHeader(headers: Record<string, string>): string | undefined {
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === 'cookie') {
                return headers[key];
            }
        }
        return undefined;
    }
}