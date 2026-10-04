import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface XpathRule {
    name: string;
    pattern: RegExp;
}

const XPATH_FUNCTIONS = 'count|name|local-name|string-length|substring|substring-before|substring-after|contains|starts-with|string|concat|normalize-space|translate|position|last|text|node|doc|document|boolean|not|number';

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: XpathRule[] = [
    {
        // ' or '1'='1   " or ""="   ' or 1=1 or ''='   -- the same quote must close the comparison
        name: 'quoted_tautology',
        pattern: /(['"])\s*(?:or|and)\s+(?:\1[^'"]*\1|\d+)\s*(?:=|!=|<|>)\s*(?:\1[^'"]*|\d+)/i,
    },
    {
        // '] | //user  ') | //*   -- closing a predicate and starting a union with a new path
        name: 'predicate_breakout_union',
        pattern: /['"]?\s*[\])]\s*\|\s*\/\//,
    },
    {
        // ' and count(/*)=1 and '   ' or string-length(name(/*[1]))=4 or '   -- blind XPath probing
        name: 'blind_function_probe',
        pattern: new RegExp(`['"]\\s*(?:or|and)\\s+(?:${XPATH_FUNCTIONS})\\s*\\(`, 'i'),
    },
    {
        // //user[  /*[1]  /child::node()  ancestor::  -- absolute paths and axes inside a value
        name: 'path_expression',
        pattern: /\/\/\*|\/\*\s*\[\s*\d+\s*\]|\b(?:child|parent|ancestor|ancestor-or-self|descendant|descendant-or-self|following|following-sibling|preceding|preceding-sibling|self|attribute)::/i,
    },
    {
        // name(/*)  count(//user)  doc('http://...')
        name: 'function_on_document',
        pattern: new RegExp(`\\b(?:${XPATH_FUNCTIONS})\\s*\\(\\s*(?:/|\\.\\.|doc\\s*\\(|['"]https?:)`, 'i'),
    },
];

export default class XpathInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'xpath_injection',
            displayName: 'XPath injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = context.value;
        const matched = RULES.filter(rule => rule.pattern.test(value)).map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched })
            : safe(this.tool);
    }
}
