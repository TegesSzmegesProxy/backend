import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, methodOf, pathOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class AbsoluteUriRequest extends Tool<ToolContextType.Full> {
    private readonly allowedHosts: ReadonlySet<string>;

    constructor(config: ToolConfig<'absolute_uri_request'>) {
        super({
            id: 'absolute_uri_request',
            displayName: 'Absolute URI in request line',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
        this.allowedHosts = new Set(config.allowedHosts);
    }

    override run(context: NormalizedRequest): ToolResult {
        const method = methodOf(context);
        const target = pathOf(context);

        // "CONNECT host:443": authority-form, only meaningful to a forward proxy
        if (method === 'CONNECT' || /^[^/][^/?#]*:\d+$/.test(target)) {
            return violation(this.tool, { reason: 'authority_form_target', target: clip(target) });
        }

        // "GET http://host/path HTTP/1.1": absolute-form, which a reverse proxy may forward to that host
        const absolute = target.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)/i);
        if (!absolute) {
            return target === '*' && method !== 'OPTIONS'
                ? violation(this.tool, { reason: 'asterisk_form_target', method })
                : safe(this.tool);
        }

        const host = absolute[2].slice(absolute[2].lastIndexOf('@') + 1).replace(/:\d+$/, '').toLowerCase();
        const evidence = { scheme: absolute[1].toLowerCase(), host: clip(host), target: clip(target, 200) };

        // RFC 9112 requires servers to accept absolute-form, so our own host is merely unusual
        return this.allowedHosts.has(host)
            ? suspicious(this.tool, { reason: 'absolute_form_to_own_host', ...evidence })
            : violation(this.tool, { reason: 'absolute_form_to_foreign_host', ...evidence });
    }
}
