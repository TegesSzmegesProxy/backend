import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, accountOf, failure, hashOf, inRouteFilter, isStateChanging, methodOf,
    pathOf, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

export default class BruteForce extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) account -> login attempts.
    private readonly attempts: SlidingWindow<string>;

    constructor(private readonly config: ToolConfig<'brute_force'>, state: ToolState) {
        super({
            id: 'brute_force',
            displayName: 'Brute force',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.attempts = state.window<string>('attempts', config.windowMs, config.attempts.block + 1);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!inRouteFilter(pathOf(context), this.config.routes) || !isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }

        const account = accountOf(context);
        if (!account) {
            return failure(this.tool, { reason: 'missing_account' });
        }

        // ponytail: the proxy sees attempts before the upstream answers, so every attempt counts, not only
        // failed ones. A user who logs in successfully does not usually retry 10 times in 15 minutes.
        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const recent = await this.attempts.record(context.tenantId, hashOf(account), context.clientIp, now);
        const attempts = recent.length; // capped at the block limit + 1, which is all the comparison below needs
        const { windowMs, attempts: limits } = this.config;

        const evidence = { attempts, windowMs, sourceIps: new Set(recent.map(event => event.value)).size };
        if (attempts > limits.block) {
            return violation(this.tool, { ...evidence, limit: limits.block });
        }
        if (attempts > limits.suspicious) {
            return suspicious(this.tool, { ...evidence, threshold: limits.suspicious });
        }
        return safe(this.tool);
    }
}
