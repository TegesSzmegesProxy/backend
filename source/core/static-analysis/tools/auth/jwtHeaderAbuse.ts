import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

const BEARER = /^bearer +(\S+) *$/i;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
// "kid" is the key identifier. Verifiers often use it to build a file path or a database query,
// so each rule below corresponds to an injection into that lookup.
const KID_RULES: { name: string; pattern: RegExp }[] = [
    {
        // ../../dev/null   /etc/passwd   C:\keys\x   -- a verifier that reads the key from a file path
        name: 'kid_path_traversal',
        pattern: /(?:^|[\\/])\.\.(?:[\\/]|$)|^[\\/]|^[a-z]:[\\/]|\/(?:dev|etc|proc)\//i,
    },
    {
        // ' OR '1'='1   x' UNION SELECT ...   x'; DROP TABLE keys --
        name: 'kid_sql_injection',
        pattern: /['"`]\s*(?:or|and|union)\b|\bunion\s+(?:all\s+)?select\b|['"`)\s]--|\/\*|;\s*(?:drop|select|insert|update|delete)\b/i,
    },
    {
        // key1; id   key1 | nc ...   $(whoami)   `id`
        name: 'kid_command_injection',
        pattern: /[|;&`<>]|\$\(|\$\{/,
    },
    {
        // http://evil.example/key.pem -- a verifier that fetches the key named by "kid"
        name: 'kid_url',
        pattern: /^[a-z][a-z0-9+.-]*:\/\//i,
    },
    {
        // NUL and other control characters, raw or percent-encoded
        name: 'kid_control_character',
        pattern: /[\u0000-\u001f\u007f]|%(?:25)*(?:[01][0-9a-f]|7f)/i,
    },
];

export default class JwtHeaderAbuse extends Tool<ToolContextType.Full> {
    // asymmetric algorithms by default: a symmetric algorithm next to a public key is the "algorithm confusion" attack
    private readonly allowedAlgorithms: ReadonlySet<string>;
    private readonly allowedTypes: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'jwt_header_abuse'>) {
        super({
            id: 'jwt_header_abuse',
            displayName: 'JWT header abuse',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.allowedAlgorithms = new Set(config.allowedAlgorithms);
        this.allowedTypes = new Set(config.allowedTypes);
    }

    override run(context: NormalizedRequest): ToolResult {
        const authorization = Object.entries(context.headers ?? {}).find(([name]) => name.toLowerCase() === 'authorization')?.[1];
        const token = typeof authorization === 'string' ? authorization.match(BEARER)?.[1] : undefined;

        // No bearer token, or one that is clearly not a JWS (3 segments) or JWE (5 segments): nothing to inspect.
        if (!token || token.length > this.config.maxTokenLength) {
            return JwtHeaderAbuse.safe(this.tool);
        }

        const parts = token.split('.');
        if (parts.length !== 3 && parts.length !== 5) {
            return JwtHeaderAbuse.safe(this.tool);
        }

        const { rules, alg } = this.analyze(parts[0]);

        if (rules.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                // rule names and a sanitized algorithm only: the token, "kid" and key URLs are never included
                evidence: { rules, alg },
            };
        }

        return JwtHeaderAbuse.safe(this.tool);
    }

    private analyze(segment: string): { rules: string[]; alg?: string } {
        const rules = new Set<string>();

        if (segment.length > this.config.maxHeaderLength) {
            rules.add('oversized_header');
        }

        const decoded = JwtHeaderAbuse.decode(segment);
        if (!decoded) {
            return { rules: [...rules, 'malformed_header'] };
        }

        const { json, header } = decoded;

        // Parameter names, read from the raw JSON because JSON.parse silently keeps only the last duplicate.
        const keys = JwtHeaderAbuse.topLevelKeys(json);
        if (new Set(keys.map(key => key.toLowerCase())).size < keys.length) {
            rules.add('duplicate_header_parameter');
        }
        if (keys.some(key => key === '__proto__' || key === 'constructor' || key === 'prototype')) {
            rules.add('prototype_pollution_key');
        }

        // alg
        const rawAlg = header['alg'];
        if (typeof rawAlg !== 'string' || rawAlg.trim() === '') {
            rules.add('invalid_alg');
        } else if (rawAlg.trim().toLowerCase() === 'none') {
            rules.add('alg_none');
        } else if (this.allowedAlgorithms.has(rawAlg)) {
            // configured, so expected
        } else if (/^hs\d{3}$/i.test(rawAlg)) {
            rules.add('symmetric_alg'); // HS256/384/512 where only public-key algorithms are accepted
        } else {
            rules.add('unexpected_alg');
        }

        // keys the token supplies about itself: a verifier that trusts these accepts attacker-made tokens
        if (Object.prototype.hasOwnProperty.call(header, 'jwk') || Object.prototype.hasOwnProperty.call(header, 'x5c')) {
            rules.add('embedded_key');
        }
        for (const param of ['jku', 'x5u']) {
            if (Object.prototype.hasOwnProperty.call(header, param)) {
                rules.add(`${param}_header`);
                JwtHeaderAbuse.keyUrlRules(header[param]).forEach(rule => rules.add(rule));
            }
        }

        // kid
        if (Object.prototype.hasOwnProperty.call(header, 'kid')) {
            this.kidRules(header['kid']).forEach(rule => rules.add(rule));
        }

        // typ
        const typ = header['typ'];
        if (typ !== undefined && (typeof typ !== 'string' || !this.allowedTypes.has(typ.toLowerCase()))) {
            rules.add('unexpected_typ');
        }

        // extensions that change how the token must be processed
        if (Object.prototype.hasOwnProperty.call(header, 'crit')) rules.add('crit_header');
        if (Object.prototype.hasOwnProperty.call(header, 'zip')) rules.add('zip_header'); // JWE decompression bomb
        if (header['b64'] === false) rules.add('unencoded_payload'); // RFC 7797
        if (typeof header['cty'] === 'string' && /jwt/i.test(header['cty'])) rules.add('nested_jwt');

        // PBES2 key derivation cost is attacker-controlled through "p2c"
        const p2c = header['p2c'];
        if (p2c !== undefined && (typeof p2c !== 'number' || !Number.isInteger(p2c) || p2c < 1 || p2c > this.config.maxPbes2Iterations)) {
            rules.add('pbes2_abuse');
        }

        // alg comes from the token, so only a short, plain value is echoed back
        const alg = typeof rawAlg === 'string' && /^[A-Za-z0-9_+-]{1,20}$/.test(rawAlg) ? rawAlg : undefined;

        return { rules: [...rules], alg };
    }

    private kidRules(kid: unknown): string[] {
        if (typeof kid !== 'string') {
            return ['invalid_kid'];
        }

        const rules: string[] = [];
        if (kid.length > this.config.maxKidLength) {
            rules.push('kid_too_long');
        }

        // test the raw value and the percent-decoded value, since "%2e%2e%2f" is still "../"
        const candidates = [kid];
        try {
            const decoded = decodeURIComponent(kid);
            if (decoded !== kid) {
                candidates.push(decoded);
            }
        } catch {
            // malformed escape, so only the raw value is tested
        }

        for (const rule of KID_RULES) {
            if (candidates.some(candidate => rule.pattern.test(candidate))) {
                rules.push(rule.name);
            }
        }

        return rules;
    }

    private static keyUrlRules(value: unknown): string[] {
        if (typeof value !== 'string') {
            return ['key_url_invalid'];
        }

        let url: URL;
        try {
            url = new URL(value);
        } catch {
            return ['key_url_invalid'];
        }

        const rules: string[] = [];
        if (url.protocol !== 'https:') rules.push('key_url_not_https');
        if (url.username || url.password) rules.push('key_url_credentials');
        if (JwtHeaderAbuse.isInternalHost(url.hostname)) rules.push('key_url_internal_host');
        return rules;
    }

    // The URL parser already turns decimal, hex and octal IPv4 forms into dotted quads.
    private static isInternalHost(hostname: string): boolean {
        const host = hostname.toLowerCase().replace(/\.$/, '');

        if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
            return true;
        }
        if (host.startsWith('[')) {
            return /^\[(?:::1?\]|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:|::ffff:)/.test(host);
        }

        const match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
        if (!match) {
            return false;
        }
        const a = Number(match[1]);
        const b = Number(match[2]);
        return a === 0 || a === 10 || a === 127
            || (a === 169 && b === 254)
            || (a === 172 && b >= 16 && b <= 31)
            || (a === 192 && b === 168)
            || (a === 100 && b >= 64 && b <= 127);
    }

    // base64url -> JSON object, or undefined if any step fails (or the result isn't a plain object)
    private static decode(segment: string): { json: string; header: Record<string, unknown> } | undefined {
        if (segment === '' || !BASE64URL.test(segment)) {
            return undefined;
        }

        try {
            const json = Buffer.from(segment, 'base64url').toString('utf8');
            const parsed: unknown = JSON.parse(json);
            return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
                ? { json, header: parsed as Record<string, unknown> }
                : undefined;
        } catch {
            return undefined;
        }
    }

    // Keys of the top-level object, in order, duplicates included. The JSON has already parsed successfully,
    // so this only has to track strings (with escapes) and nesting depth.
    private static topLevelKeys(json: string): string[] {
        const keys: string[] = [];
        let depth = 0;
        let expectKey = false;

        for (let index = 0; index < json.length; index++) {
            const char = json[index];

            if (char === '"') {
                let end = index + 1;
                while (end < json.length && json[end] !== '"') {
                    end += json[end] === '\\' ? 2 : 1;
                }
                if (depth === 1 && expectKey) {
                    try {
                        keys.push(JSON.parse(json.slice(index, end + 1)) as string); // decodes escapes like "\u0061lg"
                    } catch {
                        // unreachable for input that already parsed
                    }
                    expectKey = false;
                }
                index = end;
            } else if (char === '{' || char === '[') {
                depth++;
                if (depth === 1) {
                    expectKey = true;
                }
            } else if (char === '}' || char === ']') {
                depth--;
            } else if (char === ',' && depth === 1) {
                expectKey = true;
            }
        }

        return keys;
    }

    private static safe(tool: string): ToolResult {
        return {
            tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}