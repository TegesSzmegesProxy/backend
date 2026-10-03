import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface PrototypePollutionRule {
    name: string;
    pattern: RegExp;
}

type Target = 'name' | 'key' | 'value';

// Limits for walking nested values, so a huge or deeply nested body can't make this tool slow.
const MAX_DEPTH = 6;
const MAX_NODES = 1000;

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
// Applied to field names, object keys and string values.
const RULES: PrototypePollutionRule[] = [
    {
        // __proto__  as a key, a path segment (a.__proto__.b, __proto__[x]) or inside JSON text ({"__proto__": ...})
        name: 'proto_reference',
        pattern: /(?:^|[^\w$])__proto__(?![\w$])/i,
    },
    {
        // constructor.prototype   constructor[prototype]   constructor["prototype"]
        name: 'constructor_prototype_path',
        pattern: /(?:^|[^\w$])constructor\s*(?:\.\s*|\[\s*["']?)prototype(?![\w$])/i,
    },
];

export default class PrototypePollution extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'prototype_pollution',
            displayName: 'Prototype pollution',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const seen = new Set<string>();
        const findings: { target: Target; rule: string }[] = [];

        const check = (target: Target, text: string): void => {
            for (const rule of RULES) {
                const id = `${target}|${rule.name}`;
                if (!seen.has(id) && rule.pattern.test(text)) {
                    seen.add(id);
                    findings.push({ target, rule: rule.name });
                }
            }
        };

        // the field name is attacker-controlled too ("__proto__[admin]=1" arrives as a name, not as a value)
        if (typeof context.name === 'string') {
            check('name', context.name);
        }

        PrototypePollution.walk(context.value, 0, { nodes: 0 }, check);

        if (findings.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: { name: String(context.name).slice(0, 100), location: context.location, findings },
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    // Visits every string and every object key in the value, down to MAX_DEPTH and up to MAX_NODES nodes.
    private static walk(
        value: unknown,
        depth: number,
        state: { nodes: number },
        visit: (target: Target, text: string) => void,
    ): void {
        if (depth > MAX_DEPTH || state.nodes++ >= MAX_NODES) {
            return;
        }

        if (typeof value === 'string') {
            visit('value', value);
            return;
        }

        if (Array.isArray(value)) {
            for (const item of value) {
                PrototypePollution.walk(item, depth + 1, state, visit);
            }
            return;
        }

        if (typeof value === 'object' && value !== null) {
            // Object.entries lists an own "__proto__" property, which is what JSON.parse creates
            for (const [key, child] of Object.entries(value)) {
                visit('key', key);

                // {"constructor": {"prototype": {...}}} is the same attack spread over two nested keys, so it is
                // reported as if it were the path "constructor.prototype"
                if (
                    key === 'constructor'
                    && typeof child === 'object'
                    && child !== null
                    && !Array.isArray(child)
                    && Object.prototype.hasOwnProperty.call(child, 'prototype')
                ) {
                    visit('key', 'constructor.prototype');
                }

                PrototypePollution.walk(child, depth + 1, state, visit);
            }
        }
    }
}