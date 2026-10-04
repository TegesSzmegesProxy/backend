import { timingSafeEqual } from 'node:crypto';
import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, clip, cookiesOf, fieldLeaf, header, isStateChanging, methodOf, safe,
    violation,
} from '@tessera/core/static-analysis/shared';

export default class Csrf extends Tool<ToolContextType.Full> {
    private readonly tokenFields: ReadonlySet<string>;
    private readonly tokenCookies: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'csrf'>) {
        super({
            id: 'csrf',
            displayName: 'Cross-site request forgery (CSRF)',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.tokenFields = new Set(config.tokenFields);
        this.tokenCookies = new Set(config.tokenCookies);
    }

    override run(context: NormalizedRequest): ToolResult {
        if (!isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }
        // Only ambient credentials can be forged: a request with an Authorization header was built by script
        // that already had the token, and a request without cookies carries no session to abuse.
        const cookies = cookiesOf(context);
        if (header(context, 'authorization') !== undefined || cookies.length === 0) {
            return safe(this.tool);
        }

        const fetchSite = header(context, 'sec-fetch-site')?.toLowerCase();
        if (fetchSite === 'cross-site') {
            return violation(this.tool, { reason: 'cross_site_fetch', secFetchSite: fetchSite });
        }

        const origin = header(context, 'origin') ?? Csrf.originOf(header(context, 'referer'));
        if (origin !== undefined && !this.config.allowedOrigins.includes(origin)) {
            return violation(this.tool, { reason: 'origin_mismatch', origin: clip(origin) });
        }

        const token = this.config.tokenHeaders.map(name => header(context, name)).find(value => value !== undefined && value !== '')
            ?? context.fields.find(field => this.tokenFields.has(fieldLeaf(field.name)) && typeof field.value === 'string' && field.value !== '')?.value as string | undefined;
        if (token === undefined) {
            return violation(this.tool, { reason: 'missing_csrf_token' });
        }

        // double-submit pattern: when the token is also in a cookie, the two must match
        const cookieToken = cookies.find(([name]) => this.tokenCookies.has(name.toLowerCase()))?.[1];
        if (cookieToken !== undefined && !Csrf.equal(cookieToken, token)) {
            return violation(this.tool, { reason: 'csrf_token_mismatch' });
        }

        return safe(this.tool);
    }

    private static originOf(referer: string | undefined): string | undefined {
        if (referer === undefined) return undefined;
        try {
            return new URL(referer).origin;
        } catch {
            return 'invalid';
        }
    }

    private static equal(a: string, b: string): boolean {
        let left = a;
        try {
            left = decodeURIComponent(a); // cookie values are often percent-encoded
        } catch {
            // compare as is
        }
        const x = Buffer.from(left);
        const y = Buffer.from(b);
        return x.length === y.length && timingSafeEqual(x, y);
    }
}
