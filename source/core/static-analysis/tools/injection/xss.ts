import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface XssRule {
    name: string;
    pattern: RegExp;
}

const RULES: XssRule[] = [
    {
        // <script>, </script>, <script src=...>
        name: 'script_tag',
        pattern: /<\s*\/?\s*script\b/i,
    },
    {
        // <img onerror=...>, <body onload=...>, <svg onload = ...>
        name: 'event_handler_attribute',
        pattern: /<[^>]*\bon[a-z]{3,20}\s*=/i,
    },
    {
        // javascript:alert(1), vbscript:..., also with whitespace/control chars inside the scheme
        name: 'script_uri',
        pattern: /\b(?:j\s*a\s*v\s*a|v\s*b)\s*s\s*c\s*r\s*i\s*p\s*t\s*:/i,
    },
    {
        // data:text/html;base64,... in href/src/etc.
        name: 'data_html_uri',
        pattern: /\bdata\s*:\s*(?:text\/html|application\/xhtml\+xml|image\/svg\+xml)/i,
    },
    {
        // <iframe>, <object>, <embed>, <applet>
        name: 'embedding_tag',
        pattern: /<\s*(?:iframe|object|embed|applet)\b/i,
    },
    {
        // <svg>, <math> are common mXSS / filter-bypass vectors
        name: 'svg_or_math_tag',
        pattern: /<\s*(?:svg|math)\b/i,
    },
    {
        // <meta http-equiv="refresh" ...>, <base href=...>, <link rel=import ...>
        name: 'document_manipulation_tag',
        pattern: /<\s*(?:meta|base|link)\b[^>]*(?:http-equiv|href|rel)\s*=/i,
    },
    {
        // style="...expression(...)" / url(javascript:...) / -moz-binding
        name: 'css_script',
        pattern: /\bexpression\s*\(|\burl\s*\(\s*['"]?\s*javascript:|-moz-binding/i,
    },
    {
        // document.cookie, document.write, window.location, eval(...), innerHTML = ...
        name: 'dangerous_js_sink',
        pattern: /\bdocument\s*\.\s*(?:cookie|write|domain)\b|\b(?:eval|settimeout|setinterval)\s*\(\s*['"`]|\.\s*innerhtml\s*=/i,
    },
    {
        // "><script>, '><img ...  (breaking out of an attribute)
        name: 'attribute_breakout',
        pattern: /['"]\s*>\s*<\s*[a-z]/i,
    },
];

export default class Xss extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'xss',
            displayName: 'Cross-site scripting (XSS)',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SAFE',
                evidence: undefined,
            };
        }

        const value = context.value;
        const matched = RULES
            .filter(rule => rule.pattern.test(value))
            .map(rule => rule.name);

        if (matched.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: matched,
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}