import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface CsvRule {
    name: string;
    test: (value: string) => boolean;
}

// Spreadsheet functions that reach outside the sheet or run commands.
const DANGEROUS_FUNCTIONS = /\b(?:HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|WEBSERVICE|FILTERXML|CALL|REGISTER|EXEC|DDE|RTD|INDIRECT)\s*\(/i;

// Only the start of the value matters: that is where a spreadsheet decides it is looking at a formula.
const RULES: CsvRule[] = [
    {
        // =1+1   =HYPERLINK(...)   @SUM(...)   (= and @ always start a formula)
        name: 'formula_prefix',
        test: value => /^\s*[=@]/.test(value),
    },
    {
        // +cmd|' /C calc'!A0   -2+3+cmd|...   +A1   -- but not "+48 600 100 200", "-12.5" or "- a list item"
        name: 'signed_formula',
        test: value => /^\s*[+-]/.test(value) && !/^\s*[+-]?[\d\s().,/-]*$/.test(value) && /[(|!]|\b[A-Za-z]{1,3}\d+\b/.test(value),
    },
    {
        // a leading tab or carriage return hides the formula character from naive checks
        name: 'control_prefix',
        test: value => /^[\t\r]+\s*[=+\-@]/.test(value),
    },
    {
        // cmd|'/C calc'!A0  -- Dynamic Data Exchange call, wherever it sits
        name: 'dde_payload',
        test: value => /\w+\|\s*['"]?[^'"|]*['"]?\s*!\s*\w+/.test(value) && /[=+\-@]/.test(value.trimStart()[0] ?? ''),
    },
    {
        name: 'dangerous_function',
        test: value => /^\s*[=+\-@]/.test(value) && DANGEROUS_FUNCTIONS.test(value),
    },
];

export default class CsvInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'csv_injection',
            displayName: 'CSV / formula injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = context.value;
        const matched = RULES.filter(rule => rule.test(value)).map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched })
            : safe(this.tool);
    }
}
