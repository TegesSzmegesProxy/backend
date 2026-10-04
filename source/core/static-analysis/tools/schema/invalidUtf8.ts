import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

// A UTF-16 half without its partner: what a decoder produces from broken bytes, and invalid in UTF-8.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
// U+FFFE, U+FFFF and the U+FDD0-FDEF block are permanently unassigned "noncharacters".
const NONCHARACTER = /[﷐-﷯￾￿]/;
// U+FFFD: the decoder already replaced bytes it couldn't read.
const REPLACEMENT = /�/;
// "+ADw-script+AD4-": UTF-7, which some old parsers still honour and filters don't see as "<script>"
const UTF7_SEQUENCE = /\+A(?:Dw|D4|CI|Cc|DE|EA|F8)-/;

export default class InvalidUtf8 extends Tool<ToolContextType.Full> {
    private readonly allowedCharsets: ReadonlySet<string>;

    constructor(config: ToolConfig<'invalid_utf8'>) {
        super({
            id: 'invalid_utf8',
            displayName: 'Invalid UTF-8 and charset',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
        this.allowedCharsets = new Set(config.allowedCharsets);
    }

    override run(context: NormalizedRequest): ToolResult {
        const violations: { source: string; rule: string }[] = [];
        const suspicions: { source: string; rule: string }[] = [];

        const charsets = [...(header(context, 'content-type') ?? '').matchAll(/;\s*charset\s*=\s*"?([^";\s]+)/gi)].map(match => match[1].toLowerCase());
        for (const charset of charsets) {
            if (!this.allowedCharsets.has(charset)) violations.push({ source: 'content-type', rule: `unexpected_charset:${clip(charset, 30)}` });
        }

        const texts: { source: string; text: string }[] = [];
        for (const field of context.fields) {
            const source = `${field.location}:${clip(field.name, 50)}`;
            texts.push({ source: `${source}:name`, text: String(field.name) });
            if (typeof field.value === 'string') texts.push({ source, text: field.value });
        }
        for (const [name, value] of Object.entries(context.headers ?? {})) {
            texts.push({ source: `header:${clip(name, 50)}`, text: String(value) });
        }

        for (const { source, text } of texts) {
            if (LONE_SURROGATE.test(text)) violations.push({ source, rule: 'lone_surrogate' });
            if (NONCHARACTER.test(text)) violations.push({ source, rule: 'noncharacter' });
            // a pasted "�" is possible, so a replacement character is only suspicious
            if (REPLACEMENT.test(text)) suspicions.push({ source, rule: 'replacement_character' });
            if (UTF7_SEQUENCE.test(text)) suspicions.push({ source, rule: 'utf7_sequence' });
        }

        if (violations.length > 0) return violation(this.tool, { findings: [...violations, ...suspicions].slice(0, 10) });
        return suspicions.length > 0 ? suspicious(this.tool, { findings: suspicions.slice(0, 10) }) : safe(this.tool);
    }
}
