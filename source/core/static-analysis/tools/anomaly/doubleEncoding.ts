import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 8192;
const MAX_ROUNDS = 4;

// Characters filters usually look for, which an attacker wants to survive one decoding pass.
const SPECIAL = new Set(['.', '/', '\\', '<', '>', '"', "'", ';', '&', '=', '\0', '\r', '\n', '(', ')', '`', '|', ':']);

const RULES: { name: string; pattern: RegExp }[] = [
    // %252e -> %2e -> "."   %25252f -> %252f -> %2f -> "/"
    { name: 'percent_encoded_percent', pattern: /%25(?:25)*[0-9a-f]{2}/i },
    // %%32%65 -> %2e, a percent sign followed by an escape that completes it
    { name: 'nested_hex_escape', pattern: /%%[0-9a-f]{2}%[0-9a-f]{2}|%%[0-9a-f]{2}[0-9a-f]|%[0-9a-f]%[0-9a-f]{2}/i },
    // %u002e: IIS-style unicode escape, often stacked with %25
    { name: 'iis_unicode_escape', pattern: /%(?:25)*u00[0-9a-f]{2}/i },
];

export default class DoubleEncoding extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'double_encoding',
            displayName: 'Double encoding',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || !context.value.includes('%')) {
            return safe(this.tool);
        }

        const value = context.value.slice(0, MAX_LENGTH);
        const rules = RULES.filter(rule => rule.pattern.test(value)).map(rule => rule.name);
        if (rules.length === 0) {
            return safe(this.tool);
        }

        // Only layers that end in a filtered character matter: "100%2525" -> "100%" is not an evasion.
        const revealed = DoubleEncoding.revealed(value);
        if (revealed.length === 0) {
            return safe(this.tool);
        }

        return suspicious(this.tool, { name: clip(context.name), location: context.location, rules, revealed });
    }

    // Decodes layer by layer and returns the special characters that only appear after the first layer.
    private static revealed(value: string): string[] {
        const decodeOnce = (text: string): string => text
            .replace(/%u([0-9a-f]{4})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
            .replace(/%([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));

        const first = decodeOnce(value);
        let current = first;
        for (let round = 1; round < MAX_ROUNDS; round++) {
            const next = decodeOnce(current);
            if (next === current) break;
            current = next;
        }

        const afterFirst = new Set([...first].filter(char => SPECIAL.has(char)));
        const late = [...current].filter(char => SPECIAL.has(char) && !afterFirst.has(char));
        return [...new Set(late)].map(char => JSON.stringify(char));
    }
}
