import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

type Severity = 'POLICY_VIOLATION' | 'SUSPICIOUS';

// RFC 6750 token68: letters, digits and - . _ ~ + / with optional trailing "=" padding.
const TOKEN68 = /^[A-Za-z0-9._~+/-]+=*$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

// Values clients send when a variable was never set: "Authorization: Bearer undefined".
const PLACEHOLDERS = new Set(['null', 'undefined', 'nan', 'none', 'false', 'true', 'bearer', 'token', '[object object]']);

// JWT header parameters that make the verifier fetch or trust a key supplied by the token itself.
const KEY_REFERENCE_PARAMS = ['jku', 'x5u', 'jwk'];

const SEVERITY: Record<string, Severity> = {
    missing_token: 'POLICY_VIOLATION',
    whitespace_in_token: 'POLICY_VIOLATION',
    too_long: 'POLICY_VIOLATION',
    invalid_characters: 'POLICY_VIOLATION',
    placeholder_token: 'POLICY_VIOLATION',
    malformed_jwt: 'POLICY_VIOLATION',
    empty_signature: 'POLICY_VIOLATION',
    invalid_claim: 'POLICY_VIOLATION',
    expired: 'POLICY_VIOLATION',
    not_yet_valid: 'POLICY_VIOLATION',
    alg_none: 'SUSPICIOUS',
    unexpected_alg: 'SUSPICIOUS',
    key_reference_header: 'SUSPICIOUS',
};

export default class InvalidBearer extends Tool<ToolContextType.Full> {
    private readonly allowedAlgorithms: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'invalid_bearer'>) {
        super({
            id: 'invalid_bearer',
            displayName: 'Invalid bearer token',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.allowedAlgorithms = new Set(config.allowedAlgorithms);
    }

    override run(context: NormalizedRequest): ToolResult {
        const header = Object.entries(context.headers ?? {}).find(([name]) => name.toLowerCase() === 'authorization')?.[1];

        // No header, or another scheme (Basic, Digest, ...): not a bearer token, so nothing to validate here.
        // Whether authentication is required at all is an endpoint policy, not this tool's job.
        if (typeof header !== 'string' || !/^bearer(?![^\s])/i.test(header)) {
            return InvalidBearer.safe(this.tool);
        }

        const { rules, alg } = this.analyze(header.slice('bearer'.length));

        if (rules.length > 0) {
            const violation = rules.some(rule => SEVERITY[rule] === 'POLICY_VIOLATION');
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: violation ? 'POLICY_VIOLATION' : 'SUSPICIOUS',
                // rule names and the (sanitized) algorithm only: the token itself is never included
                evidence: { rules, alg },
            };
        }

        return InvalidBearer.safe(this.tool);
    }

    private analyze(rest: string): { rules: string[]; alg?: string } {
        // leading spaces are allowed between scheme and token (RFC 7235); anything else is not
        const token = rest.replace(/^ +/, '').replace(/ +$/, '');

        if (token === '') return { rules: ['missing_token'] };
        if (/\s/.test(token)) return { rules: ['whitespace_in_token'] };
        if (token.length > this.config.maxTokenLength) return { rules: ['too_long'] };
        if (!TOKEN68.test(token)) return { rules: ['invalid_characters'] };
        if (PLACEHOLDERS.has(token.toLowerCase())) return { rules: ['placeholder_token'] };

        // Exactly two dots means a compact JWS (header.payload.signature). Anything else is treated as an
        // opaque token, which has no structure to check beyond the rules above.
        const parts = token.split('.');
        return parts.length === 3 ? this.analyzeJwt(parts) : { rules: [] };
    }

    private analyzeJwt([headerPart, payloadPart, signaturePart]: string[]): { rules: string[]; alg?: string } {
        const header = InvalidBearer.decode(headerPart);
        const payload = InvalidBearer.decode(payloadPart);

        if (!header || !payload) {
            return { rules: ['malformed_jwt'] };
        }

        const rules: string[] = [];

        const rawAlg = header['alg'];
        if (typeof rawAlg !== 'string' || rawAlg === '') {
            rules.push('malformed_jwt');
        } else if (rawAlg.toLowerCase() === 'none') {
            rules.push('alg_none');
        } else if (!this.allowedAlgorithms.has(rawAlg)) {
            rules.push('unexpected_alg');
        }

        if (signaturePart === '') {
            rules.push('empty_signature');
        }

        if (KEY_REFERENCE_PARAMS.some(param => Object.prototype.hasOwnProperty.call(header, param))) {
            rules.push('key_reference_header');
        }

        const now = Date.now() / 1000;

        const exp = payload['exp'];
        if (exp !== undefined) {
            if (typeof exp !== 'number' || !Number.isFinite(exp)) {
                rules.push('invalid_claim');
            } else if (exp + this.config.clockSkewSeconds < now) {
                rules.push('expired');
            }
        }

        const nbf = payload['nbf'];
        if (nbf !== undefined) {
            if (typeof nbf !== 'number' || !Number.isFinite(nbf)) {
                rules.push('invalid_claim');
            } else if (nbf - this.config.clockSkewSeconds > now) {
                rules.push('not_yet_valid');
            }
        }

        // alg comes from the token, so only a short, plain value is echoed back
        const alg = typeof rawAlg === 'string' && /^[A-Za-z0-9_-]{1,20}$/.test(rawAlg) ? rawAlg : undefined;

        return { rules: [...new Set(rules)], alg };
    }

    // base64url -> JSON object, or undefined if any step fails (or the result isn't a plain object)
    private static decode(segment: string): Record<string, unknown> | undefined {
        if (!BASE64URL.test(segment)) {
            return undefined;
        }

        try {
            const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
            return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
                ? (parsed as Record<string, unknown>)
                : undefined;
        } catch {
            return undefined;
        }
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