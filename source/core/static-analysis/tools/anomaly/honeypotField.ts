import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, safe, violation } from '@tessera/core/static-analysis/shared';

export default class HoneypotField extends Tool<ToolContextType.Full> {
    // hidden inputs the forms render off-screen: a person never sees them, a form-filling bot fills them in
    private readonly fields: ReadonlySet<string>;

    constructor(config: ToolConfig<'honeypot_field'>) {
        super({
            id: 'honeypot_field',
            displayName: 'Honeypot field',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        this.fields = new Set(config.fields);
    }

    override run(context: NormalizedRequest): ToolResult {
        const filled = context.fields.filter(field =>
            this.fields.has(fieldLeaf(field.name))
            && field.value !== null
            && field.value !== undefined
            && String(field.value).trim() !== '',
        );

        if (filled.length > 0) {
            // names only: the value is whatever the bot typed
            return violation(this.tool, { fields: filled.slice(0, 5).map(field => clip(field.name)) });
        }
        return safe(this.tool);
    }
}
