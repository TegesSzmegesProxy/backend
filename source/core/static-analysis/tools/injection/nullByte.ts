import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface NullByteRule {
    name: string;
    test: (value: string) => boolean;
}

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: NullByteRule[] = [
    {
        // the actual NUL character
        name: 'raw_null_byte',
        test: value => value.includes('\u0000'),
    },
    {
        // %00, and double-encoded %2500 / %252500
        name: 'percent_encoded',
        test: value => /%(?:25)*00/i.test(value),
    },
    {
        // the text "\u0000" or "\x00", as sent in JSON or source-code style payloads
        name: 'escape_sequence',
        test: value => /\\(?:u0000|x00)/i.test(value),
    },
    {
        // &#0;  &#00  &#x0;  &#x00  (but not &#05 or &#x0a)
        name: 'html_entity',
        test: value => /&#(?:0+(?!\d)|x0+(?![0-9a-f]))/i.test(value),
    },
];

export default class NullByte extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'null_byte',
            displayName: 'Null byte',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        // the field name is attacker-controlled too, so it is checked along with the value
        const targets: { target: 'name' | 'value'; text: string }[] = [];
        if (typeof context.name === 'string') {
            targets.push({ target: 'name', text: context.name });
        }
        if (typeof context.value === 'string') {
            targets.push({ target: 'value', text: context.value });
        }

        const findings = targets.flatMap(({ target, text }) =>
            RULES.filter(rule => rule.test(text)).map(rule => ({ target, rule: rule.name })),
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