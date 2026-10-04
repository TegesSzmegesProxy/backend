import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, accountOf, distinct, failure, hashOf, inRouteFilter, pathOf,
    routeKey, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

export default class AccountEnumeration extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client -> { identity, route } pairs.
    private readonly probes: SlidingWindow<{ identity: string; route: string }>;

    constructor(private readonly config: ToolConfig<'account_enumeration'>, state: ToolState) {
        super({
            id: 'account_enumeration',
            displayName: 'Account enumeration',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.probes = state.window('probes', config.windowMs, config.identities.block * 4 + 4);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const path = pathOf(context);
        // endpoints that answer differently for existing and unknown accounts
        if (!inRouteFilter(path, this.config.routes)) {
            return safe(this.tool);
        }

        const identity = accountOf(context);
        if (!identity) {
            return safe(this.tool); // e.g. GET of the form page; no identity is being probed
        }
        if (!context.clientIp) {
            return failure(this.tool, { reason: 'missing_client_identity' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const events = await this.probes.record(context.tenantId, context.clientIp, { identity: hashOf(identity), route: routeKey(path) }, now);
        const identities = distinct(events, value => value.identity).size;
        const routes = [...distinct(events, value => value.route)];

        const { windowMs, identities: limits } = this.config;
        const evidence = { distinctIdentities: identities, routes: routes.slice(0, 5), windowMs };
        if (identities > limits.block) {
            return violation(this.tool, { ...evidence, limit: limits.block });
        }
        if (identities > limits.suspicious) {
            return suspicious(this.tool, { ...evidence, threshold: limits.suspicious });
        }
        return safe(this.tool);
    }
}
