import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    ExpiringMap, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, clip, hashOf, header, matchesRoute, pathOf, safe, violation,
} from '@tessera/core/static-analysis/shared';

export default class TimestampReplay extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) nonce -> requestId that first used it.
    private readonly nonces: ExpiringMap<string>;

    constructor(private readonly config: ToolConfig<'timestamp_replay'>, state: ToolState) {
        super({
            id: 'timestamp_replay',
            displayName: 'Timestamp replay',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        // a nonce only has to be remembered while its timestamp is still fresh
        this.nonces = state.expiring<string>('nonces', 2 * config.maxAgeMs);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const signature = this.config.signatureHeaders.map(name => header(context, name)).find(value => value !== undefined);
        const signedRoute = matchesRoute(pathOf(context), this.config.signedRoutes);
        if (!signature && !signedRoute) {
            return safe(this.tool); // not a signed request
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const timestamp = this.timestampOf(context, signature);
        if (timestamp === undefined) {
            return violation(this.tool, { reason: 'missing_timestamp' });
        }

        const age = now - timestamp;
        if (Math.abs(age) > this.config.maxAgeMs) {
            return violation(this.tool, { reason: age > 0 ? 'stale_timestamp' : 'future_timestamp', ageMs: age, maxAgeMs: this.config.maxAgeMs });
        }

        const nonce = this.config.nonceHeaders.map(name => header(context, name)).find(value => value !== undefined && value !== '');
        // without a nonce, the signature itself identifies the request
        const replayKey = nonce ?? signature;
        if (replayKey === undefined) {
            return violation(this.tool, { reason: 'missing_nonce' });
        }

        const key = hashOf(replayKey);
        const firstUse = await this.nonces.get(context.tenantId, key);
        // the same requestId means the pipeline is analyzing the same request again, not a replay
        if (firstUse !== undefined && firstUse !== context.requestId) {
            return violation(this.tool, { reason: nonce ? 'reused_nonce' : 'reused_signature', nonce: nonce ? clip(nonce, 64) : undefined });
        }
        await this.nonces.set(context.tenantId, key, context.requestId);

        return safe(this.tool);
    }

    // Header timestamp, or "t=<unix>" inside a Stripe-style signature header. Seconds or milliseconds.
    private timestampOf(request: NormalizedRequest, signature: string | undefined): number | undefined {
        const raw = this.config.timestampHeaders.map(name => header(request, name)).find(value => value !== undefined)
            ?? signature?.match(/(?:^|,)\s*t=(\d+)/)?.[1];
        if (raw === undefined) {
            return undefined;
        }
        const value = /^\d+$/.test(raw.trim()) ? Number(raw) : Date.parse(raw);
        if (!Number.isFinite(value) || value <= 0) {
            return undefined;
        }
        return value < 1e12 ? value * 1000 : value;
    }
}
