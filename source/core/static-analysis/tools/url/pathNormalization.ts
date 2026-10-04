import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, matchesRoute, pathOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

interface PathRule {
    name: string;
    pattern: RegExp;
}

// Applied to the raw path (the endpoint keeps it exactly as received, before any decoding).
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: PathRule[] = [
    { name: 'double_slash', pattern: /\/\/+/ },
    { name: 'dot_segment', pattern: /(?:^|\/)\.{1,2}(?:\/|$)/ },
    { name: 'encoded_slash_or_backslash', pattern: /%(?:25)*(?:2f|5c)/i },
    { name: 'encoded_dot', pattern: /%(?:25)*2e/i },
    { name: 'backslash', pattern: /\\/ },
    // /admin;jsessionid=x  /admin;/  /..;/  -- Tomcat/Spring strip ";..." after routing decisions are made
    { name: 'path_parameter', pattern: /;[^/?]*/ },
    { name: 'encoded_null_or_control', pattern: /%(?:25)*(?:00|0[9ad]|1[0-9a-f]|7f)/i },
    // /admin%20  /admin.  /ADMIN with a trailing dot or space that some stacks trim
    { name: 'trailing_dot_or_space', pattern: /(?:\.|%20|\s)+(?:\/|$)/ },
    { name: 'overlong_utf8', pattern: /%c0%(?:ae|af|2f|5c)|%e0%80%ae/i },
];

export default class PathNormalization extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'path_normalization'>) {
        super({
            id: 'path_normalization',
            displayName: 'Path normalization',
            category: ToolCategory.Url,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const raw = pathOf(context).split('?')[0];
        const matched = RULES.filter(rule => rule.pattern.test(raw)).map(rule => rule.name);
        if (matched.length === 0) {
            return safe(this.tool);
        }

        // the path an ACL may see vs the path the backend will serve
        const normalized = PathNormalization.normalize(raw);
        const evidence = { rules: matched, path: clip(raw, 200), normalized: clip(normalized, 200) };

        // the raw path doesn't look privileged but resolves to a privileged route: an ACL bypass attempt
        const { privilegedRoutes } = this.config;
        if (matchesRoute(normalized, privilegedRoutes) && !matchesRoute(raw, privilegedRoutes)) {
            return violation(this.tool, { ...evidence, reason: 'resolves_to_privileged_route' });
        }
        return suspicious(this.tool, evidence);
    }

    // Decode (bounded), drop path parameters, fold slashes, resolve dot segments, trim trailing dots/spaces.
    private static normalize(path: string): string {
        let current = path;
        for (let round = 0; round < 3; round++) {
            let next: string;
            try {
                next = decodeURIComponent(current.replace(/%c0%ae/gi, '.').replace(/%c0%af/gi, '/'));
            } catch {
                break;
            }
            if (next === current) break;
            current = next;
        }

        const segments: string[] = [];
        for (const segment of current.replace(/\\/g, '/').split('/')) {
            const part = segment.split(';')[0]; // "/..;/" is ".." to Tomcat
            const clean = /^\.+$/.test(part) ? part : part.replace(/[.\s]+$/, '');
            if (clean === '' || clean === '.') continue;
            if (clean === '..') segments.pop();
            else segments.push(clean);
        }
        return `/${segments.join('/')}`.toLowerCase();
    }
}
