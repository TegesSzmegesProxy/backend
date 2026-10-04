import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, clip, headerValues, matchesRoute, pathOf, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

const KNOWN_SCHEMES = new Set(['basic', 'bearer', 'digest', 'negotiate', 'ntlm', 'hoba', 'mutual', 'aws4-hmac-sha256', 'dpop']);
const TOKEN68 = /^[A-Za-z0-9\-._~+/]+=*$/;
const MAX_LENGTH = 8192;

export default class BasicAuthAnomaly extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'basic_auth_anomaly'>) {
        super({
            id: 'basic_auth_anomaly',
            displayName: 'Authorization header anomaly',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const values = headerValues(context, 'authorization');
        if (values.length === 0) {
            return safe(this.tool);
        }

        const findings: string[] = [];
        let unknownScheme: string | undefined;

        for (const value of values) {
            if (value.length > MAX_LENGTH) {
                findings.push('oversized_header');
                continue;
            }
            const match = value.match(/^([A-Za-z0-9!#$%&'*+.^_`|~-]+)(?: +(.*))?$/);
            if (!match) {
                findings.push('malformed_header');
                continue;
            }
            const scheme = match[1].toLowerCase();
            const credentials = (match[2] ?? '').trim();

            if (scheme === 'basic') {
                if (!matchesRoute(pathOf(context), this.config.basicAuthRoutes)) {
                    findings.push('basic_auth_not_allowed_on_route');
                }
                const problem = BasicAuthAnomaly.checkBasic(credentials);
                if (problem) findings.push(problem);
            } else if (scheme === 'bearer') {
                if (credentials === '' || !TOKEN68.test(credentials)) findings.push('malformed_bearer_token');
            } else if (!KNOWN_SCHEMES.has(scheme)) {
                unknownScheme = clip(match[1], 30);
            }
        }

        if (findings.length > 0) {
            return violation(this.tool, { findings: [...new Set(findings)], unknownScheme });
        }
        if (unknownScheme) {
            return suspicious(this.tool, { findings: ['unknown_scheme'], unknownScheme });
        }
        return safe(this.tool);
    }

    // base64("user:password"), RFC 7617
    private static checkBasic(credentials: string): string | undefined {
        if (credentials === '' || !/^[A-Za-z0-9+/]+={0,2}$/.test(credentials) || credentials.length % 4 !== 0) {
            return 'malformed_basic_credentials';
        }
        const decoded = Buffer.from(credentials, 'base64').toString('utf8');
        if (!decoded.includes(':')) {
            return 'basic_credentials_without_colon';
        }
        if (/[\u0000-\u001f\u007f]/.test(decoded)) {
            return 'control_characters_in_credentials';
        }
        if (decoded.indexOf(':') === 0) {
            return 'empty_username';
        }
        return undefined;
    }
}
