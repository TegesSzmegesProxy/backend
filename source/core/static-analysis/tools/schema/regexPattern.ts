import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

export default class RegexPattern extends Tool<ToolContextType.Field> {
    private readonly anchored: RegExp;

    constructor(private readonly config: ToolConfig<'regex_pattern'>) {
        super({
            id: 'regex_pattern',
            displayName: 'Allowlist pattern',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
        // patterns are allowlists and must match the whole value, so they are anchored here whatever the config says
        this.anchored = new RegExp(`^(?:${config.pattern})$`, config.flags);
    }

    override run(context: RequestField): ToolResult {
        if (context.value === undefined || context.value === null) {
            return safe(this.tool);
        }
        if (typeof context.value !== 'string' && typeof context.value !== 'number') {
            return violation(this.tool, { name: clip(context.name), location: context.location, reason: 'not_a_scalar' });
        }

        const value = String(context.value);
        // longer values are rejected without running the pattern, so accidental backtracking can't be abused
        if (value.length > this.config.maxLength) {
            return violation(this.tool, { name: clip(context.name), location: context.location, reason: 'too_long', length: value.length });
        }

        return this.anchored.test(value)
            ? safe(this.tool)
            : violation(this.tool, { name: clip(context.name), location: context.location, reason: 'pattern_mismatch', pattern: clip(this.config.pattern, 200) });
    }
}
