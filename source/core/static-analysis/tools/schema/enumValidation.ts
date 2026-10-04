import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

export default class EnumValidation extends Tool<ToolContextType.Field> {
    constructor(private readonly config: ToolConfig<'enum_validation'>) {
        super({
            id: 'enum_validation',
            displayName: 'Enum validation',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const allowed = this.config.values;
        if (context.value === undefined || context.value === null) {
            return safe(this.tool); // absence is RequiredFields' concern
        }

        // exact match, no case folding: "pln" and "PLN" are different values to the backend
        const value = context.value;
        const ok = allowed.some(option => option === value || (typeof option === 'number' && typeof value === 'string' && String(option) === value));

        return ok
            ? safe(this.tool)
            : violation(this.tool, { name: clip(context.name), location: context.location, value: clip(value, 50), allowed: allowed.slice(0, 20) });
    }
}
