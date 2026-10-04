import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, analyzeGraphql, graphqlDocuments, safe, suspicious, walkValue } from '@tessera/core/static-analysis/shared';

// GraphQL syntax inside a variable value: someone concatenating a query, or probing for it.
const SYNTAX_IN_VARIABLE = /^\s*(?:query|mutation|subscription|fragment)\b[\s\S]*\{|\}\s*(?:query|mutation|fragment)\s+\w*\s*[({]|\.\.\.\s*on\s+\w+\s*\{|__schema\s*\{/;
// A string argument that closes itself and opens new selections: user(name: "x\") { password } #")
const ARGUMENT_BREAKOUT = /\\?"\s*\)\s*\{[^}]*\}\s*(?:#|\w+\s*[({])/;

export default class GraphqlInjection extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'graphql_injection'>) {
        super({
            id: 'graphql_injection',
            displayName: 'GraphQL injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const documents = graphqlDocuments(context);
        if (documents.length === 0) {
            return safe(this.tool);
        }

        // aliases: e.g. 100 aliased login mutations in one request is brute force in a single call;
        // directives: @a@a@a@a... overloading; repeats: field duplication
        const { maxSameFieldAliases, maxDirectivesPerField, maxSameFieldRepeats, maxFragments } = this.config;
        const findings: { document: number; rule: string; detail?: unknown }[] = [];

        documents.forEach(({ query, variables }, document) => {
            const stats = analyzeGraphql(query);

            if (stats.fragmentCycle) {
                findings.push({ document, rule: 'circular_fragment' });
            }
            if (stats.fragments > maxFragments) {
                findings.push({ document, rule: 'fragment_flood', detail: stats.fragments });
            }
            for (const [field, count] of stats.aliasedFields) {
                if (count > maxSameFieldAliases) {
                    findings.push({ document, rule: 'alias_batching', detail: { field: field.slice(0, 50), count } });
                }
            }
            if (stats.maxDirectivesPerField > maxDirectivesPerField) {
                findings.push({ document, rule: 'directive_overloading', detail: stats.maxDirectivesPerField });
            }
            for (const [field, count] of stats.fieldCounts) {
                if (count > maxSameFieldRepeats) {
                    findings.push({ document, rule: 'field_duplication', detail: { field: field.slice(0, 50), count } });
                }
            }
            if (ARGUMENT_BREAKOUT.test(query)) {
                findings.push({ document, rule: 'argument_breakout' });
            }

            let injectedVariable = false;
            walkValue(variables, (kind, text) => {
                if (kind === 'value' && !injectedVariable && SYNTAX_IN_VARIABLE.test(text)) injectedVariable = true;
            }, { maxDepth: 8, maxNodes: 1000 });
            if (injectedVariable) {
                findings.push({ document, rule: 'graphql_syntax_in_variables' });
            }
        });

        return findings.length > 0 ? suspicious(this.tool, { findings: findings.slice(0, 10) }) : safe(this.tool);
    }
}
