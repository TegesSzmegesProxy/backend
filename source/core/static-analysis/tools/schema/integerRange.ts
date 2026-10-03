import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class IntegerRange extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'integer_range',
            displayName: 'Integer range',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const min = 0; // hard-coded until we have enough infrastructure to support tool configuration
        const max = 100; // inclusive bounds, also hard-coded for now

        if (typeof context.value === 'number' && Number.isInteger(context.value)) {
            if (context.value < min || context.value > max) {
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