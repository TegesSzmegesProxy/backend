import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface ControlCharacterRule {
    name: string;
    test: (value: string, singleLine: boolean) => boolean;
}

// Locations where a line break has no legitimate place (HTTP header and URL components).
// Adjust to the values RequestField.location actually takes.
const SINGLE_LINE_LOCATIONS = new Set(['query', 'header', 'headers', 'path', 'cookie']);

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
// NUL (U+0000) is left out on purpose because the NullByte tool already covers it.
const RULES: ControlCharacterRule[] = [
    {
        // C0 controls except tab, LF, CR (and NUL), plus DEL and the C1 range
        name: 'raw_control_character',
        test: value => /[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(value),
    },
    {
        // %01-%08, %0b, %0c, %0e-%1f, %7f, including double-encoded forms like %2507
        name: 'encoded_control_character',
        test: value => /%(?:25)*(?:0[1-8bcef]|1[0-9a-f]|7f)/i.test(value),
    },
    {
        // CR, LF, U+2028 and U+2029 where only a single line is expected (header / log injection)
        name: 'line_break_in_single_line_field',
        test: (value, singleLine) => singleLine && /[\r\n\u2028\u2029]/.test(value),
    },
    {
        // %0d and %0a, including double-encoded, where only a single line is expected (CRLF injection)
        name: 'encoded_line_break_in_single_line_field',
        test: (value, singleLine) => singleLine && /%(?:25)*0[ad]/i.test(value),
    },
    {
        // LRM, RLM, ALM, embeddings, overrides and isolates: visually reorder text ("Trojan Source")
        name: 'bidi_control',
        test: value => /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(value),
    },
    {
        // zero-width space / joiners, word joiner, BOM: invisible characters used for spoofing and filter bypass
        name: 'zero_width_character',
        test: value => /[\u200b-\u200d\u2060\ufeff]/.test(value),
    },
];

export default class ControlCharacter extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'control_character',
            displayName: 'Control character',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const singleLine = SINGLE_LINE_LOCATIONS.has(String(context.location).toLowerCase());

        // the field name is attacker-controlled too, and is always expected to be a single line
        const targets: { target: 'name' | 'value'; text: string; singleLine: boolean }[] = [];
        if (typeof context.name === 'string') {
            targets.push({ target: 'name', text: context.name, singleLine: true });
        }
        if (typeof context.value === 'string') {
            targets.push({ target: 'value', text: context.value, singleLine });
        }

        const findings = targets.flatMap(({ target, text, singleLine: isSingleLine }) =>
            RULES.filter(rule => rule.test(text, isSingleLine)).map(rule => ({ target, rule: rule.name })),
        );

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
}