import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, lookupCidr, matchesRoute, normalizeIp, pathOf, routeKey, safe,
    suspicious, violation,
} from '@tessera/core/static-analysis/shared';

export default class GeoPolicy extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'geo_policy'>) {
        super({
            id: 'geo_policy',
            displayName: 'Geo policy',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const ip = normalizeIp(context.clientIp);
        const country = lookupCidr(ip, this.config.geoIp)?.country;
        const path = pathOf(context);
        const routeRule = this.config.routes
            .filter(rule => matchesRoute(path, [rule.route]))
            .sort((a, b) => b.route.length - a.route.length)[0];

        if (!country) {
            // an address the database can't place: only an allowlisted route needs to know
            return routeRule
                ? suspicious(this.tool, { reason: 'unknown_country_on_restricted_route', route: routeKey(path).slice(0, 100) })
                : safe(this.tool);
        }

        if (this.config.deny.includes(country)) {
            return violation(this.tool, { reason: 'country_denied', country });
        }
        if (routeRule && !routeRule.allow.includes(country)) {
            return violation(this.tool, { reason: 'country_not_allowed_for_route', country, route: routeRule.route, allowed: routeRule.allow });
        }
        if (this.config.expected !== undefined && !this.config.expected.includes(country)) {
            return suspicious(this.tool, { reason: 'unusual_country', country });
        }
        return safe(this.tool);
    }
}
