import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

export default class RequiredFields extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'required_fields'>) {
        super({
            id: 'required_fields',
            displayName: 'Required fields',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const body = typeof context.body === 'object' && context.body !== null && !Array.isArray(context.body)
            ? (context.body as Record<string, unknown>)
            : {};

        // null and "" count as missing: an empty password is not a password
        const missing = this.config.fields.filter(name => {
            const value = Object.prototype.hasOwnProperty.call(body, name) ? body[name] : undefined;
            return value === undefined || value === null || (typeof value === 'string' && value.trim() === '');
        });

        return missing.length > 0 ? violation(this.tool, { endpoint: clip(context.endpoint, 200), missing }) : safe(this.tool);
    }
}
