import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, analyzeGraphql, graphqlDocuments, safe, violation } from '@tessera/core/static-analysis/shared';

export default class GraphqlComplexity extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'graphql_complexity'>) {
        super({
            id: 'graphql_complexity',
            displayName: 'GraphQL complexity',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const documents = graphqlDocuments(context);
        if (documents.length === 0) {
            return safe(this.tool);
        }

        // cost: fields weighted by the page sizes of their ancestors; batch: operations in one HTTP request (array body)
        const { maxDepth, maxCost, maxAliases, maxFields, maxBatch, maxQueryBytes } = this.config;
        const reasons: { rule: string; value: number; limit: number }[] = [];
        if (documents.length > maxBatch) {
            reasons.push({ rule: 'batch_too_large', value: documents.length, limit: maxBatch });
        }

        let depth = 0;
        let cost = 0;
        let aliases = 0;
        let fields = 0;
        for (const { query } of documents) {
            if (query.length > maxQueryBytes) {
                reasons.push({ rule: 'query_too_long', value: query.length, limit: maxQueryBytes });
                continue; // don't spend time measuring a document that already fails
            }
            const stats = analyzeGraphql(query);
            depth = Math.max(depth, stats.depth);
            cost += stats.cost;
            aliases += stats.aliases;
            fields += stats.fields;
        }

        if (depth > maxDepth) reasons.push({ rule: 'too_deep', value: depth, limit: maxDepth });
        if (cost > maxCost) reasons.push({ rule: 'too_expensive', value: cost, limit: maxCost });
        if (aliases > maxAliases) reasons.push({ rule: 'too_many_aliases', value: aliases, limit: maxAliases });
        if (fields > maxFields) reasons.push({ rule: 'too_many_fields', value: fields, limit: maxFields });

        return reasons.length > 0 ? violation(this.tool, { reasons }) : safe(this.tool);
    }
}
