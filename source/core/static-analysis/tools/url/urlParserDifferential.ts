import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface DifferentialRule {
    name: string;
    pattern: RegExp;
}

const MAX_LENGTH = 4096;

// Tricks that make two URL parsers (the validator and the HTTP client) disagree about the host.
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: DifferentialRule[] = [
    {
        // http:\\evil.com   http:/\evil.com   https:\/evil.com   -- WHATWG treats \ as /, many libraries don't
        name: 'backslash_in_authority',
        pattern: /^[a-z][a-z0-9+.-]*:[/\\]*\\|^[/\\]{2}[^/\\]*\\/i,
    },
    {
        // http://a@b@evil.com   -- which @ ends the userinfo differs between parsers
        name: 'multiple_at_signs',
        pattern: /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@[^/?#]*@/i,
    },
    {
        // http://trusted.com#@evil.com   http://trusted.com?@evil.com   http://evil.com\@trusted.com
        name: 'delimiter_before_at',
        pattern: /^[a-z][a-z0-9+.-]*:\/\/[^/@]*[#?\\][^/]*@/i,
    },
    {
        // http:evil.com   https:/evil.com   -- missing slashes, accepted by lenient parsers as an absolute URL
        name: 'missing_authority_slashes',
        pattern: /^https?:(?!\/\/)[/\\]?[a-z0-9]/i,
    },
    {
        // ///evil.com   /\evil.com   \/evil.com   -- browsers read these as protocol-relative
        name: 'mixed_or_extra_slashes',
        pattern: /^(?:\/{3,}|\/\\|\\\/|\\\\)[^/\\]/,
    },
    {
        // http://evil.com%2f@trusted.com   http://trusted%2ecom   -- encoded delimiters inside the authority
        name: 'encoded_authority_delimiter',
        pattern: /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*%(?:2f|5c|40|3f|23|2e|00)/i,
    },
    {
        // tab, newline or other whitespace/control characters that one parser strips and another stops at
        name: 'whitespace_in_url',
        pattern: /^[a-z][a-z0-9+.-]*:\/\/\S*[\t\r\n\u0000-\u001f]/i,
    },
    {
        // http://evil。com   http://ｅｖｉｌ.com   -- Unicode dots and fullwidth letters normalized differently
        name: 'unicode_in_authority',
        pattern: /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*[。．｡！-～]/i,
    },
    {
        // http://trusted.com:80@evil.com   -- a "port" that is really userinfo
        name: 'port_like_userinfo',
        pattern: /^[a-z][a-z0-9+.-]*:\/\/[^/?#@]*:\d*@/i,
    },
];

export default class UrlParserDifferential extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'url_parser_differential',
            displayName: 'URL parser differential',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        // leading whitespace and control characters are stripped by browsers before parsing
        const value = context.value.slice(0, MAX_LENGTH).replace(/^[\u0000- ]+/, '');
        if (!/^[a-z][a-z0-9+.-]*:|^[/\\]{2}/i.test(value)) {
            return safe(this.tool); // not shaped like a URL at all
        }

        const matched = RULES.filter(rule => rule.pattern.test(value)).map(rule => rule.name);
        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched, value: value.slice(0, 200) })
            : safe(this.tool);
    }
}
