import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, bearerToken, clip, cookiesOf, decodeJwt, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

const JWT_SHAPE = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;
// path traversal, quotes, SQL and shell syntax in a key id that the server may use as a file path or query
const KID_INJECTION = /\.\.[/\\]|^[/\\]|['";`|$]|\bunion\b|\bselect\b|--|\/\*|\bdev\/null\b/i;

interface Finding {
    source: string;
    rule: string;
    detail?: string;
}

export default class JwtHeaderAttacks extends Tool<ToolContextType.Full> {
    // the algorithms the issuer signs with; anything else, HS256 included, is a confusion attempt
    private readonly allowedAlgorithms: ReadonlySet<string>;
    private readonly knownCritical: ReadonlySet<string>;
    private readonly trustedKeyHosts: ReadonlySet<string>;

    constructor(config: ToolConfig<'jwt_header_attacks'>) {
        super({
            id: 'jwt_header_attacks',
            displayName: 'JWT header attacks',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.allowedAlgorithms = new Set(config.allowedAlgorithms);
        this.knownCritical = new Set(config.knownCritical);
        this.trustedKeyHosts = new Set(config.trustedKeyHosts);
    }

    override run(context: NormalizedRequest): ToolResult {
        const findings = JwtHeaderAttacks.tokens(context).flatMap(({ source, token }) => this.inspect(source, token));

        if (findings.length === 0) {
            return safe(this.tool);
        }
        // everything except an unknown "crit" extension is a header no honest client produces
        return findings.every(finding => finding.rule === 'unknown_critical_header')
            ? suspicious(this.tool, { findings })
            : violation(this.tool, { findings: findings.slice(0, 10) });
    }

    // Bearer token, JWT-looking cookies and JWT-looking fields.
    private static tokens(context: NormalizedRequest): { source: string; token: string }[] {
        const tokens: { source: string; token: string }[] = [];
        const bearer = bearerToken(context);
        if (bearer && JWT_SHAPE.test(bearer)) tokens.push({ source: 'authorization', token: bearer });
        for (const [name, value] of cookiesOf(context)) {
            if (JWT_SHAPE.test(value)) tokens.push({ source: `cookie:${clip(name, 50)}`, token: value });
        }
        for (const field of context.fields) {
            if (typeof field.value === 'string' && JWT_SHAPE.test(field.value)) tokens.push({ source: `${field.location}:${clip(field.name, 50)}`, token: field.value });
        }
        return tokens.slice(0, 10);
    }

    private inspect(source: string, token: string): Finding[] {
        const decoded = decodeJwt(token);
        if (!decoded) {
            return [{ source, rule: 'malformed_token' }];
        }

        const { header, signature } = decoded;
        const findings: Finding[] = [];
        const alg = typeof header['alg'] === 'string' ? header['alg'] : undefined;

        if (alg === undefined || alg.toLowerCase() === 'none') {
            findings.push({ source, rule: 'alg_none', detail: clip(alg ?? 'missing', 20) });
        } else if (/^HS\d+$/i.test(alg) && !this.allowedAlgorithms.has(alg.toUpperCase())) {
            // RS256 -> HS256: the server's public key used as an HMAC secret
            findings.push({ source, rule: 'algorithm_confusion', detail: alg });
        } else if (!this.allowedAlgorithms.has(alg)) {
            findings.push({ source, rule: 'unexpected_algorithm', detail: clip(alg, 20) });
        }

        if (signature === '' && alg?.toLowerCase() !== 'none') {
            findings.push({ source, rule: 'missing_signature' });
        }

        const kid = header['kid'];
        if (kid !== undefined && (typeof kid !== 'string' || KID_INJECTION.test(kid))) {
            findings.push({ source, rule: 'kid_injection', detail: clip(kid, 60) });
        }

        for (const name of ['jku', 'x5u']) {
            const url = header[name];
            if (url !== undefined && !this.trustedKeyUrl(url)) {
                findings.push({ source, rule: `untrusted_${name}`, detail: clip(url, 100) });
            }
        }

        // a public key embedded in the token itself, so the token verifies against the attacker's key
        if (header['jwk'] !== undefined || header['x5c'] !== undefined) {
            findings.push({ source, rule: 'embedded_key' });
        }

        if (Array.isArray(header['crit']) && header['crit'].some(name => !this.knownCritical.has(String(name)))) {
            findings.push({ source, rule: 'unknown_critical_header' });
        }

        return findings;
    }

    private trustedKeyUrl(value: unknown): boolean {
        if (typeof value !== 'string') return false;
        try {
            const url = new URL(value);
            return url.protocol === 'https:' && !url.username && !url.password && this.trustedKeyHosts.has(url.hostname.toLowerCase());
        } catch {
            return false;
        }
    }
}
