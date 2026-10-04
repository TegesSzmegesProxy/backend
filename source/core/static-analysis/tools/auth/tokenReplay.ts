import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    ExpiringMap, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, clip, fieldLeaf, hashOf, inRouteFilter, pathOf, routeKey, safe,
    suspicious,
} from '@tessera/core/static-analysis/shared';

interface FirstUse {
    requestId: string;
    clientIp: string;
    at: number;
}

export default class TokenReplay extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) route|token hash -> first use.
    private readonly used: ExpiringMap<FirstUse>;
    private readonly tokenFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'token_replay'>, state: ToolState) {
        super({
            id: 'token_replay',
            displayName: 'Single-use token replay',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.used = state.expiring<FirstUse>('used', config.memoryMs);
        this.tokenFields = new Set(config.tokenFields);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const path = pathOf(context);
        if (!inRouteFilter(path, this.config.routes)) {
            return safe(this.tool);
        }

        const tokens = context.fields.filter(field =>
            this.tokenFields.has(fieldLeaf(field.name)) && typeof field.value === 'string' && field.value.length >= this.config.minTokenLength,
        );
        if (tokens.length === 0) {
            return safe(this.tool);
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const replays: { field: string; firstUsedMsAgo: number; sameClient: boolean }[] = [];

        for (const token of tokens) {
            // the token itself is never stored, only its hash
            const key = `${routeKey(path)}|${hashOf(String(token.value))}`;
            const first = await this.used.get(context.tenantId, key);
            if (first === undefined) {
                await this.used.set(context.tenantId, key, { requestId: context.requestId, clientIp: context.clientIp, at: now });
            } else if (first.requestId !== context.requestId) {
                // the same requestId means the pipeline is analyzing the same request again, not a replay
                replays.push({ field: clip(token.name), firstUsedMsAgo: now - first.at, sameClient: first.clientIp === context.clientIp });
            }
        }

        // suspicious rather than a violation: a double click or a mail scanner prefetching the link reuses
        // the token too; a different client reusing it is the stronger signal, reported in sameClient
        return replays.length > 0 ? suspicious(this.tool, { replays }) : safe(this.tool);
    }
}
