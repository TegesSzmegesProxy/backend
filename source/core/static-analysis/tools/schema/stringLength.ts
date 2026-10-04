import { RequestField } from '@tessera/shared/contracts/Request';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class StringLength extends Tool<ToolContextType.Field> {
    constructor (private readonly config: { minLength?: number; maxLength?: number }) {
        super({
            id: 'string_length',
            displayName: 'String length',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value === 'string') {
            if (this.config.minLength !== undefined && context.value.length < this.config.minLength) {
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'POLICY_VIOLATION',
                    evidence: `${context.value.length} < ${this.config.minLength}`,
                }
            } else if (this.config.maxLength !== undefined && context.value.length > this.config.maxLength) {
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'POLICY_VIOLATION',
                    evidence: `${context.value.length} > ${this.config.maxLength}`,
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
