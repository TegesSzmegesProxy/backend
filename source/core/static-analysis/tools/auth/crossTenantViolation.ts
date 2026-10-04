import { NormalizedRequest } from '@tessera/shared/contracts/Request';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class CrossTenantViolation extends Tool<ToolContextType.Full> {
    // hard-coded until we have enough infrastructure to support tool configuration
    private static readonly TENANT_HEADER = 'x-tenant-id';
    private static readonly TENANT_CLAIMS = ['tenant_id', 'tenantId', 'tid', 'tenant'];
    private static readonly MAX_TOKEN_LENGTH = 16384;
    private static readonly MAX_ECHO_LENGTH = 64;

    constructor() {
        super({
            id: 'cross_tenant_violation',
            displayName: 'Cross-tenant violation',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const headerValue = this.getHeader(context.headers, CrossTenantViolation.TENANT_HEADER);
        const token = this.getBearerToken(context.headers);

        // nothing to compare against
        if (headerValue === undefined || token === undefined) {
            return this.safe();
        }

        const segments = token.split('.');
        if (segments.length !== 3) {
            // opaque token or JWE: there are no claims we can read
            return this.safe();
        }

        const violations: string[] = [];
        const suspicious: string[] = [];

        if (token.length > CrossTenantViolation.MAX_TOKEN_LENGTH) {
            return this.result('SUSPICIOUS', [`JWT length ${token.length} > ${CrossTenantViolation.MAX_TOKEN_LENGTH}`]);
        }

        const payload = this.decodePayload(segments[1]);
        if (payload === undefined) {
            return this.result('SUSPICIOUS', ['malformed JWT payload']);
        }

        // multiple X-Tenant-ID headers get comma-joined by most servers; which value wins is ambiguous
        if (headerValue.includes(',')) {
            suspicious.push('multiple values in X-Tenant-ID header');
        }

        const claims = new Map<string, string>();
        for (const name of CrossTenantViolation.TENANT_CLAIMS) {
            if (!(name in payload)) {
                continue;
            }
            const raw = payload[name];
            if (typeof raw === 'string' || typeof raw === 'number') {
                claims.set(name, String(raw));
            } else {
                suspicious.push(`unsupported type for JWT claim "${name}"`);
            }
        }

        // token has no tenant claim: tenant-agnostic tokens exist, so this isn't a violation
        if (claims.size === 0 && suspicious.length === 0) {
            return this.safe();
        }

        if (new Set(claims.values()).size > 1) {
            suspicious.push(`conflicting tenant claims in JWT (${[...claims.keys()].join(', ')})`);
        }

        for (const [name, value] of claims) {
            if (value !== headerValue) {
                violations.push(
                    `X-Tenant-ID ${this.echo(headerValue)} does not match JWT claim "${name}" ${this.echo(value)}`,
                );
            }
        }

        if (violations.length > 0) {
            return this.result('POLICY_VIOLATION', [...violations, ...suspicious]);
        }

        if (suspicious.length > 0) {
            return this.result('SUSPICIOUS', suspicious);
        }

        return this.safe();
    }

    /** Decodes without verifying the signature. */
    private decodePayload(segment: string): Record<string, unknown> | undefined {
        try {
            const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
            if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
                return parsed as Record<string, unknown>;
            }
        } catch {
            // fall through
        }
        return undefined;
    }

    private getBearerToken(headers: Record<string, string>): string | undefined {
        const value = this.getHeader(headers, 'authorization');
        if (value === undefined) {
            return undefined;
        }
        const match = /^Bearer\s+(\S+)$/i.exec(value.trim());
        return match?.[1];
    }

    /** Header names are case-insensitive, and normalization may not have lowercased them. */
    private getHeader(headers: Record<string, string>, name: string): string | undefined {
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === name) {
                return headers[key];
            }
        }
        return undefined;
    }

    /** Tenant IDs are client-controlled: truncate and quote them so they can't forge log lines. */
    private echo(value: string): string {
        return JSON.stringify(value.slice(0, CrossTenantViolation.MAX_ECHO_LENGTH));
    }

    private safe(): ToolResult {
        return { tool: this.tool, status: 'SUCCESS', verdict: 'SAFE', evidence: undefined };
    }

    private result(verdict: 'SUSPICIOUS' | 'POLICY_VIOLATION', evidence: string[]): ToolResult {
        return { tool: this.tool, status: 'SUCCESS', verdict, evidence };
    }
}