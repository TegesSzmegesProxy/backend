import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, bearerToken, decodeJwt, hasCredentials, inRouteFilter, pathOf, routeKey, safe,
    suspicious, violation,
} from '@tessera/core/static-analysis/shared';

export default class ForcedBrowsing extends Tool<ToolContextType.Full> {
    private readonly privilegedRoles: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'forced_browsing'>) {
        super({
            id: 'forced_browsing',
            displayName: 'Forced browsing',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.privilegedRoles = new Set(config.privilegedRoles);
    }

    override run(context: NormalizedRequest): ToolResult {
        let path = pathOf(context);
        try {
            path = decodeURIComponent(path); // "/%61dmin" is still "/admin"
        } catch {
            // keep the raw path
        }
        if (!inRouteFilter(path, this.config.routes)) {
            return safe(this.tool);
        }

        const route = routeKey(path).slice(0, 200);
        if (!hasCredentials(context)) {
            return violation(this.tool, { route, reason: 'unauthenticated_access_to_privileged_route' });
        }

        // Tessera never authenticates anyone; it only reads the claims the client presents. An opaque session
        // can't be read, so only a JWT whose claims name no privileged role is reported.
        const bearer = bearerToken(context);
        const claims = bearer ? decodeJwt(bearer)?.payload : undefined;
        if (claims) {
            const roles = ForcedBrowsing.roles(claims);
            if (!roles.some(role => this.privilegedRoles.has(role))) {
                return suspicious(this.tool, { route, reason: 'low_privilege_token', roles: roles.slice(0, 10) });
            }
        }

        return safe(this.tool);
    }

    private static roles(claims: Record<string, unknown>): string[] {
        const values: unknown[] = [];
        for (const claim of ['role', 'roles', 'groups', 'scope', 'scp', 'permissions']) {
            const value = claims[claim];
            if (Array.isArray(value)) values.push(...value);
            else if (typeof value === 'string') values.push(...value.split(/[\s,]+/));
        }
        return values.map(value => String(value).toLowerCase().replace(/^role_/, '')).filter(Boolean);
    }
}
