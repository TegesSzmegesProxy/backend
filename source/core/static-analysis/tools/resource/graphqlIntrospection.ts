import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, analyzeGraphql, graphqlDocuments, safe, violation } from '@tessera/core/static-analysis/shared';

export default class GraphqlIntrospection extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'graphql_introspection'>) {
        super({
            id: 'graphql_introspection',
            displayName: 'GraphQL introspection',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        if (this.config.allowIntrospection) {
            return safe(this.tool);
        }

        // __typename is used by every client cache (Apollo, urql) and reveals nothing; __schema and __type do
        const used = new Set<string>();
        for (const { query } of graphqlDocuments(context)) {
            for (const field of analyzeGraphql(query).introspection) used.add(field);
        }

        return used.size > 0
            ? violation(this.tool, { reason: 'introspection_not_allowed', fields: [...used] })
            : safe(this.tool);
    }
}
