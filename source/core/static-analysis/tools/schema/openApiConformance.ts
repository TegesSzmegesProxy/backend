import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, methodOf, safe, violation } from '@tessera/core/static-analysis/shared';

// Always allowed, whatever the description says.
const UNIVERSAL_METHODS = new Set(['OPTIONS', 'HEAD']);

export default class OpenApiConformance extends Tool<ToolContextType.Full> {
    private readonly queryParameters: ReadonlySet<string>;

    // The step belongs to one documented endpoint, so the policy router has already matched the method and
    // path (unknown endpoints get the tenant's unknown-endpoint behavior); what is left is the parameters.
    constructor(config: ToolConfig<'openapi_conformance'>) {
        super({
            id: 'openapi_conformance',
            displayName: 'OpenAPI conformance',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
        this.queryParameters = new Set(config.queryParameters);
    }

    override run(context: NormalizedRequest): ToolResult {
        if (UNIVERSAL_METHODS.has(methodOf(context))) {
            return safe(this.tool);
        }

        // body properties are AdditionalProperties' concern; this tool checks the parameters around the body
        const undocumented = [...new Set(context.fields
            .filter(field => field.location === 'query')
            .map(field => field.name.split(/[.[]/)[0]))]
            .filter(name => !this.queryParameters.has(name));
        if (undocumented.length > 0) {
            return violation(this.tool, { reason: 'undocumented_parameter', endpoint: clip(context.endpoint, 200), parameters: undocumented.slice(0, 10).map(name => clip(name, 50)) });
        }

        return safe(this.tool);
    }
}
