import { z } from 'zod';
import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

type JsonSchema = Parameters<typeof z.fromJSONSchema>[0];

// Validates the whole request body against a JSON Schema. Full context, because a schema
// constrains the shape (required keys, nesting, additionalProperties) that no single field can see.
export default class JsonSchemaCheck extends Tool<ToolContextType.Full> {
    private readonly validator: z.ZodType | undefined;

    // hard-coded until we have enough infrastructure to support tool configuration:
    // the schema comes from the constructor, and without one the tool reports ERROR rather than a false SAFE.
    constructor(schema?: JsonSchema) {
        super({
            id: 'json_schema',
            displayName: 'JSON schema',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
        this.validator = schema === undefined ? undefined : z.fromJSONSchema(schema);
    }

    override run(context: NormalizedRequest): ToolResult {
        if (!this.validator) {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { reason: 'no_schema_configured' },
            };
        }

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
