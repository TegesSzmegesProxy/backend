import { JsonWebTokenError, NotBeforeError, TokenExpiredError, verify } from 'jsonwebtoken';
import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// config.allowedAlgorithms is asymmetric only (see the contract). Never accept HS* next to a public key: an
// attacker can then sign a token with HMAC using the (public) key as the secret ("algorithm confusion").

// JWT header parameters that make a verifier fetch or trust a key supplied by the token itself.
const KEY_REFERENCE_PARAMS = ['jku', 'x5u', 'jwk'];

const BEARER = /^bearer +(\S+) *$/i;

export default class JwtValidation extends Tool<ToolContextType.Full> {
    private readonly publicKey: string;

    constructor(private readonly config: ToolConfig<'jwt_validation'>) {
        super({
            id: 'jwt_validation',
            displayName: 'JWT validation',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        // keys pasted through JSON often arrive with escaped newlines
        this.publicKey = config.publicKey.replace(/\\n/g, '\n');
    }

    override run(context: NormalizedRequest): ToolResult {
        const header = Object.entries(context.headers ?? {}).find(([name]) => name.toLowerCase() === 'authorization')?.[1];

        // No bearer token: nothing to validate. Whether authentication is required is an endpoint policy.
        const token = typeof header === 'string' ? header.match(BEARER)?.[1] : undefined;

        // Not a compact JWS (exactly two dots), so it is an opaque token this tool can't judge.
        if (!token || token.length > this.config.maxTokenLength || token.split('.').length !== 3) {
            return JwtValidation.safe(this.tool);
        }

        const rules: string[] = [];

        try {
            const { header: jwtHeader, payload } = verify(token, this.publicKey, {
                algorithms: [...this.config.allowedAlgorithms],
                issuer: this.config.issuer,
                audience: this.config.audience,
                clockTolerance: this.config.clockToleranceSeconds,
                complete: true,
            });

            if (KEY_REFERENCE_PARAMS.some(param => Object.prototype.hasOwnProperty.call(jwtHeader, param))) {
                rules.push('key_reference_header');
            }

            // jsonwebtoken only checks exp when it is present; a token that never expires is rejected here
            if (typeof payload === 'string' || typeof payload['exp'] !== 'number') {
                rules.push('missing_exp');
            }
        } catch (error) {
            rules.push(JwtValidation.classify(error));
        }

        if (rules.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                // rule names only: the token and the library's error message are never included
                evidence: { rules },
            };
        }

        return JwtValidation.safe(this.tool);
    }

    // Maps a jsonwebtoken error to a stable rule name. Order matters: the expiry and not-before errors
    // are subclasses of JsonWebTokenError.
    private static classify(error: unknown): string {
        if (error instanceof TokenExpiredError) return 'expired';
        if (error instanceof NotBeforeError) return 'not_yet_valid';

        if (error instanceof JsonWebTokenError) {
            const message = error.message.toLowerCase();
            if (message.includes('invalid signature')) return 'invalid_signature';
            if (message.includes('invalid algorithm') || message.includes('"none"')) return 'invalid_algorithm';
            if (message.includes('issuer')) return 'invalid_issuer';
            if (message.includes('audience')) return 'invalid_audience';
            if (message.includes('malformed') || message.includes('invalid token') || message.includes('invalid json')) {
                return 'malformed_token';
            }
            if (message.includes('secret or public key')) return 'invalid_key';
            return 'invalid_token';
        }

        return 'validation_failed';
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