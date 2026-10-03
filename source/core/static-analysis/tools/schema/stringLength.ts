import { RequestField } from '@tessera/shared/contracts/Request';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class StringLength extends Tool<ToolContextType.Field> {
    constructor () {
        super({
            id: 'string_length',
            displayName: 'String length',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const length = 10; // hard-coded until we have enough infrastructure to support tool configuration
        if (typeof context.value === 'string') {
            if (context.value.length < length) { // comparison operator also hard-coded for now
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'POLICY_VIOLATION',
                    evidence: `${context.value.length} < ${length}`,
                }
            } else {
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'SAFE',
                    evidence: undefined,
                }
            }
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        }
    }
}