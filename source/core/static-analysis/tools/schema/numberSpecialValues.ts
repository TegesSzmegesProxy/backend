import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

export default class NumberSpecialValues extends Tool<ToolContextType.Field> {
    constructor(private readonly config: ToolConfig<'number_special_values'>) {
        super({
            id: 'number_special_values',
            displayName: 'Special number values',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const reason = typeof context.value === 'number'
            ? NumberSpecialValues.checkNumber(context.value, this.config.maxMagnitude)
            : typeof context.value === 'string' ? NumberSpecialValues.checkText(context.value.trim(), this.config.maxMagnitude) : undefined;

        return reason
            ? violation(this.tool, { name: clip(context.name), location: context.location, reason, value: clip(context.value, 40) })
            : safe(this.tool);
    }

    private static checkNumber(value: number, maxMagnitude: number): string | undefined {
        if (Number.isNaN(value)) return 'nan';
        if (!Number.isFinite(value)) return 'infinity';
        if (Object.is(value, -0)) return 'negative_zero';
        if (Math.abs(value) > maxMagnitude) return 'near_overflow';
        // JSON.parse already rounded it: 9007199254740993 arrives as ...992, so the client meant something else
        if (Number.isInteger(value) && !Number.isSafeInteger(value)) return 'unsafe_integer';
        return undefined;
    }

    // Query strings and form fields carry numbers as text; only number-looking text is judged.
    private static checkText(text: string, maxMagnitude: number): string | undefined {
        if (/^[+-]?(?:nan|infinity|inf)$/i.test(text)) return text.toLowerCase().includes('nan') ? 'nan' : 'infinity';
        if (!/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(text)) return undefined;
        if (/^-0*(?:\.0*)?(?:e[+-]?\d+)?$/i.test(text)) return 'negative_zero';
        const value = Number(text);
        if (!Number.isFinite(value)) return 'infinity'; // "1e999"
        if (Math.abs(value) > maxMagnitude) return 'near_overflow';
        if (/^[+-]?\d+$/.test(text) && !Number.isSafeInteger(value)) return 'unsafe_integer';
        return undefined;
    }
}
