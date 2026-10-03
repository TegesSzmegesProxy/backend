import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface PathRule {
    name: string;
    test: (value: string) => boolean;
}

const MAX_DECODE_ROUNDS = 3; // %252e%252e%252f needs two; one spare for odd stacks
const MAX_LENGTH = 4096; // longer values are cut, not skipped, so padding can't hide a payload at the front

// Overlong UTF-8 / unicode spellings of "." "/" "\" that lenient servers normalize back to the plain character.
const OVERLONG: [RegExp, string][] = [
    [/%c0%ae|%e0%80%ae|%c0\.|．/gi, '.'],
    [/%c0%af|%e0%80%af|%c1%9c|%c1%1c|∕|／|⁄/gi, '/'],
    [/%c0%5c|%c1%9c|＼|∖/gi, '\\'],
];

// Files that only an attacker asks for by absolute path.
const SENSITIVE = /(?:^|\/)(?:etc\/(?:passwd|shadow|hosts|group|sudoers)|proc\/self\/|root\/\.ssh|\.ssh\/id_|windows\/(?:win\.ini|system32)|boot\.ini|web-inf\/web\.xml)/i;

const RULES: PathRule[] = [
    {
        // ../  ..\  or a trailing ".." segment, after decoding and slash normalization
        name: 'dot_dot_segment',
        test: value => value.split('/').includes('..'),
    },
    {
        // Tomcat/Spring path-parameter bypass: /..;/
        name: 'semicolon_bypass',
        test: value => /(?:^|\/)\.\.;/.test(value),
    },
    {
        name: 'sensitive_file',
        test: value => SENSITIVE.test(value),
    },
    {
        // file:// and Windows drive paths used as a path value
        name: 'absolute_path',
        test: value => /^(?:file:\/+|[a-z]:\/|\/\/[^/])/i.test(value),
    },
];

export default class PathTraversal extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'path_traversal',
            displayName: 'Path traversal',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return PathTraversal.safe(this.tool);
        }

        const normalized = PathTraversal.normalize(context.value.slice(0, MAX_LENGTH));
        const matched = RULES.filter(rule => rule.test(normalized)).map(rule => rule.name);

        if (matched.length === 0) {
            return PathTraversal.safe(this.tool);
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SUSPICIOUS',
            evidence: {
                name: String(context.name).slice(0, 100),
                location: context.location,
                rules: matched,
                normalized: normalized.slice(0, 200),
            },
        };
    }

    // Decodes until stable (bounded), strips NUL, and folds every separator spelling to "/".
    private static normalize(value: string): string {
        let current = value;
        for (let round = 0; round < MAX_DECODE_ROUNDS; round++) {
            let next = current;
            for (const [pattern, replacement] of OVERLONG) {
                next = next.replace(pattern, replacement);
            }
            try {
                next = decodeURIComponent(next);
            } catch {
                // malformed escape (e.g. a lone "%"); keep what we have, other rules still apply
            }
            if (next === current) {
                break;
            }
            current = next;
        }
        return current.replace(/\0/g, '').replace(/\\/g, '/');
    }

    private static safe(tool: string): ToolResult {
        return { tool, status: 'SUCCESS', verdict: 'SAFE', evidence: undefined };
    }
}
