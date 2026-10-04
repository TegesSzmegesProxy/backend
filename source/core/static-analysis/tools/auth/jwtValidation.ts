import { JsonWebTokenError, NotBeforeError, TokenExpiredError, verify } from 'jsonwebtoken';
import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// hard-coded until we have enough infrastructure to support tool configuration
// PEM public key (or certificate) of the token issuer. Read from the environment for now.
const PUBLIC_KEY = (process.env['TESSERA_JWT_PUBLIC_KEY'] ?? '').replace(/\\n/g, '\n');
const ISSUER = 'https://auth.example.com';
const AUDIENCE = 'tessera-api';
const CLOCK_TOLERANCE_SECONDS = 60;
const MAX_TOKEN_LENGTH = 4096;

// Asymmetric algorithms only. Never list HS* next to a public key: an attacker can then sign a token
// with HMAC using the (public) key as the secret ("algorithm confusion").
const ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'] as const;

// JWT header parameters that make a verifier fetch or trust a key supplied by the token itself.
const KEY_REFERENCE_PARAMS = ['jku', 'x5u', 'jwk'];

const BEARER = /^bearer +(\S+) *$/i;

export default class JwtValidation extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'jwt_validation',
            displayName: 'JWT validation',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const header = Object.entries(context.headers ?? {}).find(([name]) => name.toLowerCase() === 'authorization')?.[1];

        // No bearer token: nothing to validate. Whether authentication is required is an endpoint policy.
        const token = typeof header === 'string' ? header.match(BEARER)?.[1] : undefined;

        // Not a compact JWS (exactly two dots), so it is an opaque token this tool can't judge.
        if (!token || token.length > MAX_TOKEN_LENGTH || token.split('.').length !== 3) {
            return JwtValidation.safe(this.tool);
        }

        // Without a key the token can't be verified, which is different from "valid"
        if (PUBLIC_KEY === '') {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { reason: 'missing_public_key' },
            };
        }

        const rules: string[] = [];

        try {
            const { header: jwtHeader, payload } = verify(token, PUBLIC_KEY, {
                algorithms: [...ALLOWED_ALGORITHMS],
                issuer: ISSUER,
                audience: AUDIENCE,
                clockTolerance: CLOCK_TOLERANCE_SECONDS,
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