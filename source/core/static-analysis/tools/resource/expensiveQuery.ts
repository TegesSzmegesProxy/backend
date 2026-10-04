import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, methodOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class ExpensiveQuery extends Tool<ToolContextType.Full> {
    private readonly searchFields: ReadonlySet<string>;
    private readonly sortFields: ReadonlySet<string>;
    private readonly limitFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'expensive_query'>) {
        super({
            id: 'expensive_query',
            displayName: 'Expensive query',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.searchFields = new Set(config.searchFields);
        this.sortFields = new Set(config.sortFields);
        this.limitFields = new Set(config.limitFields);
    }

    override run(context: NormalizedRequest): ToolResult {
        const violations: { field: string; rule: string }[] = [];
        const suspicions: { field: string; rule: string }[] = [];

        for (const field of context.fields) {
            if (typeof field.value !== 'string' || !this.searchFields.has(fieldLeaf(field.name))) continue;
            const value = field.value.trim();
            const name = clip(field.name, 50);

            // "*", "%", "%%", ".*", "_": matches every row, so the database scans the whole table
            if (/^[*%_.?\s]+$/.test(value) && value !== '') {
                violations.push({ field: name, rule: 'wildcard_only_search' });
            } else if (/^%[^0-9a-f%]|^%$/.test(value)) {
                // "%term": a LIKE pattern with a leading wildcard can't use an index ("%20" is an escape, not a wildcard)
                suspicions.push({ field: name, rule: 'leading_wildcard' });
            } else if (/[%*].*[%*].*[%*]/.test(value)) {
                suspicions.push({ field: name, rule: 'many_wildcards' });
            } else if (value.length > 0 && value.replace(/[%*_]/g, '').length < this.config.minSearchLength && /[%*_]/.test(value)) {
                suspicions.push({ field: name, rule: 'wildcard_with_tiny_term' });
            }
        }

        // a sort over a listing with no limit sorts the whole result set
        const leaves = new Set(context.fields.map(field => fieldLeaf(field.name)));
        if (methodOf(context) === 'GET' && [...leaves].some(leaf => this.sortFields.has(leaf)) && ![...leaves].some(leaf => this.limitFields.has(leaf))) {
            suspicions.push({ field: 'sort', rule: 'unbounded_sort' });
        }

        if (violations.length > 0) return violation(this.tool, { findings: [...violations, ...suspicions] });
        return suspicions.length > 0 ? suspicious(this.tool, { findings: suspicions }) : safe(this.tool);
    }
}
