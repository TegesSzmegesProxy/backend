import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, inCidr, methodOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

// Headers many frameworks honour but caches don't include in the cache key: whatever they change in the
// response gets stored and served to everyone.
const UNKEYED_HEADERS = [
    'x-forwarded-host', 'x-forwarded-server', 'x-host', 'x-http-host-override', 'x-original-host',
    'x-original-url', 'x-rewrite-url', 'x-forwarded-scheme', 'x-forwarded-proto', 'x-forwarded-port',
    'x-forwarded-prefix', 'forwarded', 'x-original-method', 'x-http-method-override',
];
// These rewrite the routed path itself (IIS / Symfony), not just links in the page.
const PATH_OVERRIDES = new Set(['x-original-url', 'x-rewrite-url']);

export default class CachePoisoning extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'cache_poisoning'>) {
        super({
            id: 'cache_poisoning',
            displayName: 'Cache poisoning',
            category: ToolCategory.Url,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // our own proxies legitimately add forwarding headers
        if (this.config.trustedProxies.some(cidr => inCidr(context.clientIp, cidr))) {
            return safe(this.tool);
        }

        const present = UNKEYED_HEADERS
            .map(name => ({ name, value: header(context, name) }))
            .filter((entry): entry is { name: string; value: string } => entry.value !== undefined);

        const findings = present.map(({ name, value }) => ({
            header: name,
            value: clip(value, 100),
            rule: PATH_OVERRIDES.has(name) ? 'path_override_header' : 'unkeyed_header_from_client',
        }));

        // a GET with a body ("fat GET"): some caches key on the URL while the app reads the body
        const method = methodOf(context);
        if ((method === 'GET' || method === 'HEAD') && context.fields.some(field => field.location === 'body')) {
            findings.push({ header: 'body', value: '', rule: 'fat_get' });
        }

        return findings.length > 0 ? suspicious(this.tool, { findings: findings.slice(0, 10) }) : safe(this.tool);
    }
}
