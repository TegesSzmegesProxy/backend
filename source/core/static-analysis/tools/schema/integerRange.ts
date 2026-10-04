import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class IntegerRange extends Tool<ToolContextType.Field> {
    constructor(private readonly config: ToolConfig<'integer_range'>) {
        super({
            id: 'integer_range',
            displayName: 'Integer range',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const { min, max } = this.config; // inclusive; either may be unset

        if (typeof context.value === 'number' && Number.isInteger(context.value)) {
            if ((min !== undefined && context.value < min) || (max !== undefined && context.value > max)) {
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'POLICY_VIOLATION',
                    evidence: { value: context.value, min, max },
                };
            }
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}