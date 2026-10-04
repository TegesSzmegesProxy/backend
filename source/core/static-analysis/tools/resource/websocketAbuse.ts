import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, failure, metadataOf, safe, violation } from '@tessera/core/static-analysis/shared';

export default class WebsocketAbuse extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) connection -> message times.
    private readonly perSecond: SlidingWindow<true>;
    private readonly perMinute: SlidingWindow<true>;

    constructor(private readonly config: ToolConfig<'websocket_abuse'>, state: ToolState) {
        super({
            id: 'websocket_abuse',
            displayName: 'WebSocket abuse',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.perSecond = state.window<true>('perSecond', 1_000, config.maxMessagesPerSecond + 1);
        this.perMinute = state.window<true>('perMinute', 60_000, config.maxMessagesPerMinute + 1);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        // A WebSocket message is analyzed as a request carrying metadata.websocket. Adjust the key names to
        // whatever your WebSocket bridge writes.
        const websocket = metadataOf(context).websocket;
        if (!websocket) {
            return safe(this.tool); // an ordinary HTTP request
        }
        if (typeof websocket.connectionId !== 'string' || websocket.connectionId === '') {
            return failure(this.tool, { reason: 'missing_connection_id' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const key = websocket.connectionId;
        const lastSecond = (await this.perSecond.record(context.tenantId, key, true, now)).length;
        const lastMinute = (await this.perMinute.record(context.tenantId, key, true, now)).length;

        const { maxMessageBytes, maxFramesPerMessage, maxMessagesPerSecond, maxMessagesPerMinute } = this.config;
        const reasons: string[] = [];
        if (typeof websocket.messageBytes === 'number' && websocket.messageBytes > maxMessageBytes) reasons.push('message_too_large');
        // heavy fragmentation is a parser DoS
        if (typeof websocket.frames === 'number' && websocket.frames > maxFramesPerMessage) reasons.push('too_many_frames');
        if (lastSecond > maxMessagesPerSecond) reasons.push('message_rate_per_second');
        if (lastMinute > maxMessagesPerMinute) reasons.push('message_rate_per_minute');

        return reasons.length > 0
            ? violation(this.tool, { reasons, messageBytes: websocket.messageBytes, frames: websocket.frames, lastSecond, lastMinute })
            : safe(this.tool);
    }
}
