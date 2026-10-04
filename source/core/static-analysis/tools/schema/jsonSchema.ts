import { z } from 'zod';
import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

type JsonSchema = Parameters<typeof z.fromJSONSchema>[0];

// Validates the whole request body against a JSON Schema. Full context, because a schema
// constrains the shape (required keys, nesting, additionalProperties) that no single field can see.
export default class JsonSchemaCheck extends Tool<ToolContextType.Full> {
    private readonly validator: z.ZodType;

    constructor(config: ToolConfig<'json_schema'>) {
        super({
            id: 'json_schema',
            displayName: 'JSON schema',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
        this.validator = z.fromJSONSchema(config.schema as JsonSchema);
    }

    override run(context: NormalizedRequest): ToolResult {
        const result = this.validator.safeParse(context.body);
        if (result.success) {
            return { tool: this.tool, status: 'SUCCESS', verdict: 'SAFE', evidence: undefined };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'POLICY_VIOLATION',
            evidence: {
                endpoint: context.endpoint,
                // path + code + message only: zod issues can embed the received value in other fields
                issues: result.error.issues.slice(0, 5).map(issue => ({
                    path: issue.path.join('.'),
                    code: issue.code,
                    message: issue.message,
                })),
            },
        };
    }
}
