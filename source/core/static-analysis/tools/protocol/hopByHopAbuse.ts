import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, headerValues, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

// Tokens a client legitimately sends in Connection.
const STANDARD_TOKENS = new Set(['close', 'keep-alive', 'upgrade', 'te', 'http2-settings']);

// Headers a proxy would strip if the client names them in Connection, removing what the next hop relies on.
const SECURITY_HEADERS = new Set([
    'authorization', 'cookie', 'host', 'content-length', 'transfer-encoding', 'x-forwarded-for', 'x-forwarded-host',
    'x-forwarded-proto', 'x-real-ip', 'forwarded', 'x-api-key', 'x-csrf-token', 'x-xsrf-token', 'origin', 'referer',
    'x-request-id', 'x-amz-cf-id', 'cf-connecting-ip', 'true-client-ip',
]);

export default class HopByHopAbuse extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'hop_by_hop_abuse',
            displayName: 'Hop-by-hop header abuse',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const tokens = headerValues(context, 'connection')
            .flatMap(value => value.split(','))
            .map(token => token.trim().toLowerCase())
            .filter(Boolean);

        const unusual = tokens.filter(token => !STANDARD_TOKENS.has(token));
        if (unusual.length === 0) {
            return safe(this.tool);
        }

        const stripped = unusual.filter(token => SECURITY_HEADERS.has(token) || /^x-auth|^x-user|^x-forwarded-/.test(token));
        if (stripped.length > 0) {
            return violation(this.tool, { reason: 'security_header_marked_hop_by_hop', headers: stripped.slice(0, 10).map(token => clip(token, 50)) });
        }
        return suspicious(this.tool, { reason: 'custom_hop_by_hop_header', headers: unusual.slice(0, 10).map(token => clip(token, 50)) });
    }
}
