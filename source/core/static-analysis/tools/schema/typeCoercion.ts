import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

export default class TypeCoercion extends Tool<ToolContextType.Field> {
    // text-only transports, where "1" is the only way to send 1; mismatches only mean something in typed bodies
    private readonly textLocations: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'type_coercion'>) {
        super({
            id: 'type_coercion',
            displayName: 'Type coercion',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
        this.textLocations = new Set(config.textLocations);
    }

    override run(context: RequestField): ToolResult {
        const expected = this.config.expectedType;
        if (this.textLocations.has(String(context.location).toLowerCase())) {
            return safe(this.tool);
        }

        const rule = TypeCoercion.mismatch(expected, context.value)
            // {"isAdmin": ["true"]} flattened to "isAdmin.0": a scalar wrapped in an array
            ?? (/\.\d+$/.test(String(context.name)) ? 'array_wrapped_scalar' : undefined);

        // suspicious, not a violation: loose clients send "1" innocently. The risk is that a backend which
        // coerces silently sees a different value than a validator that doesn't ("0" is truthy in JS).
        return rule
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, expected, actual: typeof context.value, rule })
            : safe(this.tool);
    }

    private static mismatch(expected: string, value: unknown): string | undefined {
        switch (expected) {
            case 'boolean':
                if (typeof value === 'string' && /^(?:true|false|1|0|yes|no|on|off)$/i.test(value.trim())) return 'boolean_as_string';
                if (typeof value === 'number' && (value === 0 || value === 1)) return 'boolean_as_number';
                return undefined;
            case 'number':
            case 'integer':
                if (typeof value === 'string' && value.trim() !== '' && !Number.isNaN(Number(value))) return 'number_as_string';
                if (typeof value === 'boolean') return 'number_as_boolean';
                if (expected === 'integer' && typeof value === 'number' && !Number.isInteger(value)) return 'fraction_for_integer';
                return undefined;
            case 'string':
                if (typeof value === 'number' || typeof value === 'boolean') return 'scalar_for_string';
                return undefined;
            default:
                return undefined;
        }
    }
}
