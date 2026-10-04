import { createHmac, timingSafeEqual } from 'node:crypto';
import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, clip, cookiesOf, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

export default class CookieTampering extends Tool<ToolContextType.Full> {
    private readonly signedCookies: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'cookie_tampering'>) {
        super({
            id: 'cookie_tampering',
            displayName: 'Cookie tampering',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.signedCookies = new Set(config.signedCookies);
    }

    override run(context: NormalizedRequest): ToolResult {
        const cookies = cookiesOf(context);
        const violations: { cookie: string; rule: string }[] = [];
        const suspicions: { cookie: string; rule: string }[] = [];

        const seen = new Set<string>();
        for (const [name, rawValue] of cookies) {
            const lower = name.toLowerCase();
            // two cookies with one name: the server picks one, the attacker controls which (cookie tossing)
            if (seen.has(lower) && this.signedCookies.has(lower)) {
                suspicions.push({ cookie: clip(name, 50), rule: 'duplicate_signed_cookie' });
            }
            seen.add(lower);

            if (!this.signedCookies.has(lower)) continue;

            let value = rawValue;
            try {
                value = decodeURIComponent(rawValue);
            } catch {
                violations.push({ cookie: clip(name, 50), rule: 'malformed_encoding' });
                continue;
            }

            if (value.length > this.config.maxCookieValueBytes) {
                violations.push({ cookie: clip(name, 50), rule: 'oversized_value' });
            } else if (!value.startsWith('s:')) {
                suspicions.push({ cookie: clip(name, 50), rule: 'unsigned_value' });
            } else if (!this.verify(value.slice(2))) {
                violations.push({ cookie: clip(name, 50), rule: 'invalid_signature' });
            }
        }

        if (violations.length > 0) {
            return violation(this.tool, { findings: [...violations, ...suspicions] });
        }
        return suspicions.length > 0 ? suspicious(this.tool, { findings: suspicions }) : safe(this.tool);
    }

    // express / cookie-signature format: "<value>.<base64 HMAC-SHA256 without padding>"
    private verify(signed: string): boolean {
        const dot = signed.lastIndexOf('.');
        if (dot <= 0) {
            return false;
        }
        const value = signed.slice(0, dot);
        const expected = Buffer.from(createHmac('sha256', this.config.secret).update(value).digest('base64').replace(/=+$/, ''));
        const actual = Buffer.from(signed.slice(dot + 1));
        return expected.length === actual.length && timingSafeEqual(expected, actual);
    }
}
