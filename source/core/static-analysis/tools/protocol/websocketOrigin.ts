import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class WebsocketOrigin extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'websocket_origin'>) {
        super({
            id: 'websocket_origin',
            displayName: 'WebSocket origin',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        if ((header(context, 'upgrade') ?? '').toLowerCase() !== 'websocket') {
            return safe(this.tool);
        }

        // Browsers don't apply the same-origin policy to WebSockets and always send cookies, so the Origin
        // check is the only thing between a malicious page and the user's authenticated socket (CSWSH).
        const origin = header(context, 'origin');
        if (origin === undefined) {
            // a non-browser client (mobile app, server) — possible, but can't be told apart from a forged one
            return suspicious(this.tool, { reason: 'missing_origin' });
        }
        if (!this.config.allowedOrigins.includes(origin)) {
            return violation(this.tool, { reason: 'origin_not_allowed', origin: clip(origin) });
        }

        const version = header(context, 'sec-websocket-version');
        if (version !== undefined && version.trim() !== '13') {
            return suspicious(this.tool, { reason: 'unexpected_websocket_version', version: clip(version, 20) });
        }
        return safe(this.tool);
    }
}
