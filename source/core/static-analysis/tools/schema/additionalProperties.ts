import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

export default class AdditionalProperties extends Tool<ToolContextType.Full> {
    private readonly properties: ReadonlySet<string>;

    constructor(config: ToolConfig<'additional_properties'>) {
        super({
            id: 'additional_properties',
            displayName: 'Additional properties',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
        this.properties = new Set(config.properties);
    }

    override run(context: NormalizedRequest): ToolResult {
        if (typeof context.body !== 'object' || context.body === null || Array.isArray(context.body)) {
            return safe(this.tool); // a non-object body is a type problem, not an extra property
        }

        // own keys only: a "__proto__" key from JSON.parse is an own property and is reported too
        const undeclared = Object.keys(context.body).filter(key => !this.properties.has(key));

        return undeclared.length > 0
            ? violation(this.tool, { endpoint: clip(context.endpoint, 200), undeclared: undeclared.slice(0, 10).map(key => clip(key, 50)) })
            : safe(this.tool);
    }
}
