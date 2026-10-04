import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    ExpiringMap, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, clip, hashOf, matchesRoute, pathOf,
    safe, violation,
} from '@tessera/core/static-analysis/shared';

export default class OauthFlowValidation extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) state hash -> requestId of the callback that used it.
    private readonly usedStates: ExpiringMap<string>;

    constructor(private readonly config: ToolConfig<'oauth_flow_validation'>, state: ToolState) {
        super({
            id: 'oauth_flow_validation',
            displayName: 'OAuth flow validation',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.usedStates = state.expiring<string>('usedStates', config.stateMemoryMs);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const path = pathOf(context);
        if (matchesRoute(path, this.config.authorizeRoutes)) {
            return this.checkAuthorize(context);
        }
        if (matchesRoute(path, this.config.callbackRoutes)) {
            return this.checkCallback(context);
        }
        return safe(this.tool);
    }

    private checkAuthorize(context: NormalizedRequest): ToolResult {
        const params = OauthFlowValidation.params(context);
        const problems: string[] = [];

        const redirectUri = params.get('redirect_uri');
        // exact match, as RFC 6749 and the OAuth security BCP require: prefix matching enables open redirects
        if (redirectUri !== undefined && !this.config.redirectUris.includes(redirectUri)) {
            problems.push('unregistered_redirect_uri');
        }

        const state = params.get('state');
        if (state === undefined || state.length < this.config.minStateLength) {
            problems.push(state === undefined ? 'missing_state' : 'weak_state');
        }

        if ((params.get('response_type') ?? '').split(' ').includes('code')) {
            const method = params.get('code_challenge_method');
            if (params.get('code_challenge') === undefined) {
                if (this.config.requirePkce) problems.push('missing_pkce');
            } else if (method === undefined || method.toUpperCase() === 'PLAIN') {
                problems.push('pkce_downgrade_to_plain'); // a missing method defaults to "plain"
            }
        }
        if ((params.get('response_type') ?? '').split(' ').includes('token')) {
            problems.push('implicit_flow'); // tokens in the URL fragment; deprecated by the security BCP
        }

        return problems.length > 0
            ? violation(this.tool, { step: 'authorize', problems, redirectUri: redirectUri ? clip(redirectUri, 200) : undefined })
            : safe(this.tool);
    }

    private async checkCallback(context: NormalizedRequest): Promise<ToolResult> {
        const params = OauthFlowValidation.params(context);
        if (params.get('error') !== undefined && params.get('code') === undefined) {
            return safe(this.tool); // the provider reporting a denied consent
        }

        const state = params.get('state');
        if (state === undefined || state === '') {
            return violation(this.tool, { step: 'callback', problems: ['missing_state'] });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const key = hashOf(state);
        const firstUse = await this.usedStates.get(context.tenantId, key);
        if (firstUse !== undefined && firstUse !== context.requestId) {
            return violation(this.tool, { step: 'callback', problems: ['reused_state'] });
        }
        await this.usedStates.set(context.tenantId, key, context.requestId);

        return safe(this.tool);
    }

    // OAuth parameters from the query string or a form body, first value wins.
    private static params(context: NormalizedRequest): Map<string, string> {
        const params = new Map<string, string>();
        for (const field of context.fields) {
            const name = field.name.replace(/\.\d+$/, '');
            if (!params.has(name) && (typeof field.value === 'string' || typeof field.value === 'number')) {
                params.set(name, String(field.value));
            }
        }
        return params;
    }
}
