import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 8192;

// ASCII characters with meaning to parsers. If NFKC turns something into one of these, a later
// normalization step can turn harmless-looking input into markup, paths or queries.
const SYNTAX = /[<>'"`;/\\(){}[\]=&|$%.:@#*]/;

// Payloads that only exist after normalization ("＜ｓｃｒｉｐｔ", "ＳＥＬＥＣＴ ... ＦＲＯＭ").
const KEYWORDS = /<\s*script|javascript:|\bunion\s+select\b|\bselect\b.+\bfrom\b|\.\.\/|\bonerror\s*=|\balert\s*\(/i;

const LATIN = /\p{Script=Latin}/u;
const LOOK_ALIKE_SCRIPTS = [/\p{Script=Cyrillic}/u, /\p{Script=Greek}/u, /\p{Script=Armenian}/u, /\p{Script=Cherokee}/u];

export default class UnicodeNormalization extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'unicode_normalization',
            displayName: 'Unicode normalization',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || /^[\x00-\x7f]*$/.test(context.value)) {
            return safe(this.tool);
        }

        const value = context.value.slice(0, MAX_LENGTH);
        const normalized = value.normalize('NFKC');
        const rules: string[] = [];
        let introduced: string[] = [];

        if (normalized !== value) {
            introduced = UnicodeNormalization.introducedSyntax(value);
            if (introduced.length > 0) {
                rules.push('normalizes_to_syntax');
            }
            if (KEYWORDS.test(normalized) && !KEYWORDS.test(value)) {
                rules.push('normalizes_to_keyword');
            }
        }

        // "pаypal" with a Cyrillic "а": letters from look-alike scripts inside one word
        const mixed = value.split(/[^\p{L}\p{M}]+/u).find(word => LATIN.test(word) && LOOK_ALIKE_SCRIPTS.some(script => script.test(word)));
        if (mixed) {
            rules.push('mixed_script_word');
        }

        if (rules.length === 0) {
            return safe(this.tool);
        }

        return suspicious(this.tool, {
            name: clip(context.name),
            location: context.location,
            rules,
            introduced: introduced.slice(0, 10),
            normalized: normalized.slice(0, 120),
            word: mixed?.slice(0, 50),
        });
    }

    // Non-ASCII characters that become ASCII syntax under NFKC (＜, ＂, ﹤, ．, ／).
    private static introducedSyntax(value: string): string[] {
        const found = new Set<string>();
        for (const char of value) {
            if (char.charCodeAt(0) < 0x80) continue;
            const folded = char.normalize('NFKC');
            if (folded !== char && SYNTAX.test(folded)) {
                found.add(char);
            }
        }
        return [...found];
    }
}
