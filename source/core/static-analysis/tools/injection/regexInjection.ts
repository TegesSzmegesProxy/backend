import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface RegexRule {
    name: string;
    pattern: RegExp;
}

// Shapes that make a backtracking engine (V8, PCRE, Java, .NET) take exponential or polynomial time.
// These rules are themselves linear: no nested quantifiers.
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: RegexRule[] = [
    {
        // (a+)+   (a*)*   (\w+)*   ([a-z]+)+   (.*)+   -- a quantified group whose body ends in a quantifier
        name: 'nested_quantifier',
        pattern: /\((?:\?:)?[^()]*[+*}]\)\s*[+*{]/,
    },
    {
        // (a|a)*   (a|ab)+   (\w|\d)+   -- alternation inside a quantified group
        name: 'quantified_alternation',
        pattern: /\((?:\?:)?[^()|]+\|[^()]+\)\s*[+*{]/,
    },
    {
        // (.*a){20}   (\w+\s?){1000,}   -- large counted repetition
        name: 'large_repetition',
        pattern: /\{\s*\d{3,}\s*(?:,\s*\d*\s*)?\}|\{\s*\d+\s*,\s*\d{3,}\s*\}/,
    },
    {
        // .*.*.*   \w*\w*\w*   -- adjacent overlapping unbounded quantifiers (polynomial blowup)
        name: 'adjacent_wildcards',
        pattern: /(?:(?:\.|\\[wsdWSD]|\[[^\]]+\])[*+]){3,}/,
    },
    {
        // (?<=...) (?=...) with quantifiers, and backreferences that force backtracking: (a+)\1
        name: 'backreference_or_lookaround',
        pattern: /\\[1-9]|\(\?<?[=!][^)]*[+*][^)]*\)/,
    },
];

export default class RegexInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'regex_injection',
            displayName: 'Regex injection (ReDoS)',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        // a value with no regex syntax at all can't be a catastrophic pattern
        if (typeof context.value !== 'string' || !/[+*{|\\]/.test(context.value)) {
            return safe(this.tool);
        }

        const value = context.value.slice(0, 4096);
        const matched = RULES.filter(rule => rule.pattern.test(value)).map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched, pattern: value.slice(0, 100) })
            : safe(this.tool);
    }
}
