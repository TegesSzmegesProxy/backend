import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, matchesRoute, methodOf, pathOf, routeKey, safe, violation } from '@tessera/core/static-analysis/shared';

// Verbs that only exist for debugging or proxying and are a classic source of XST and proxy abuse.
const DANGEROUS = new Set(['TRACE', 'TRACK', 'CONNECT', 'DEBUG']);
const STANDARD = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', ...DANGEROUS]);

export default class MethodAnomaly extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'method_anomaly'>) {
        super({
            id: 'method_anomaly',
            displayName: 'HTTP method anomaly',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const method = methodOf(context);
        const path = pathOf(context);

        if (DANGEROUS.has(method)) {
            return violation(this.tool, { method, reason: 'dangerous_method' });
        }
        if (!STANDARD.has(method)) {
            return violation(this.tool, { method: method.slice(0, 20), reason: 'unknown_method' });
        }

        const allowed = this.allowedFor(path);
        if (!allowed.includes(method)) {
            return violation(this.tool, { method, route: routeKey(path).slice(0, 100), allowed, reason: 'method_not_allowed_for_route' });
        }

        return safe(this.tool);
    }

    // The most specific configured route wins ("/api/users/42" uses "/api/users").
    private allowedFor(path: string): string[] {
        const match = this.config.routes
            .filter(entry => matchesRoute(path, [entry.route]))
            .sort((a, b) => b.route.length - a.route.length)[0];
        return match ? match.methods : this.config.defaultMethods;
    }
}
