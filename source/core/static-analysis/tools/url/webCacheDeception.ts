import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, methodOf, pathOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

// Personal, uncacheable pages: the targets of cache deception.
const SENSITIVE_SEGMENTS = /\/(?:account|profile|settings|me|user|users|orders|billing|checkout|cart|dashboard|admin|api|wallet|messages|inbox)(?:\/|$|;|%)/i;

// Extensions CDNs cache by default.
const STATIC_EXTENSION = /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|map|txt|pdf|zip|mp4|webm)$/i;

// Characters the origin treats as the end of the path but the cache does not: /profile;x.css  /profile%3fx.css
const DELIMITERS = /(?:;|%3b|%23|%3f|%00|%0a|%0d|%09|\/\.\.%2f|%2f\.\.%2f|\.\.%2f)/i;

export default class WebCacheDeception extends Tool<ToolContextType.Full> {
    // where real static files live; a static extension anywhere else is a disguise
    private readonly staticPrefixes: readonly string[];

    constructor(config: ToolConfig<'web_cache_deception'>) {
        super({
            id: 'web_cache_deception',
            displayName: 'Web cache deception',
            category: ToolCategory.Url,
            contextType: ToolContextType.Full,
        });
        this.staticPrefixes = config.staticPrefixes.map(prefix => prefix.toLowerCase());
    }

    override run(context: NormalizedRequest): ToolResult {
        if (!['GET', 'HEAD'].includes(methodOf(context))) {
            return safe(this.tool); // caches only store GET/HEAD responses
        }

        const path = pathOf(context).split('?')[0];
        const lower = path.toLowerCase();
        if (!STATIC_EXTENSION.test(lower) || this.staticPrefixes.some(prefix => lower.startsWith(prefix))) {
            return safe(this.tool);
        }

        const rules: string[] = [];
        if (SENSITIVE_SEGMENTS.test(lower)) rules.push('static_extension_on_dynamic_route');
        if (DELIMITERS.test(lower)) rules.push('path_delimiter_before_extension');
        // /account/profile/nonexistent.css: an extra segment the origin ignores but the cache keys on
        if (/\/[^/]+\/[^/]*\.[a-z0-9]+$/i.test(lower) && SENSITIVE_SEGMENTS.test(lower.slice(0, lower.lastIndexOf('/') + 1))) {
            rules.push('appended_static_segment');
        }

        return rules.length > 0 ? suspicious(this.tool, { rules: [...new Set(rules)], path: clip(path, 200) }) : safe(this.tool);
    }
}
