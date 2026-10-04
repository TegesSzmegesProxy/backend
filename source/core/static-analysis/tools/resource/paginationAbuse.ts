import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, safe, violation } from '@tessera/core/static-analysis/shared';

export default class PaginationAbuse extends Tool<ToolContextType.Full> {
    private readonly pageSizeFields: ReadonlySet<string>;
    private readonly offsetFields: ReadonlySet<string>;
    private readonly pageFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'pagination_abuse'>) {
        super({
            id: 'pagination_abuse',
            displayName: 'Pagination abuse',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.pageSizeFields = new Set(config.pageSizeFields);
        this.offsetFields = new Set(config.offsetFields);
        this.pageFields = new Set(config.pageFields);
    }

    override run(context: NormalizedRequest): ToolResult {
        // a deep OFFSET scans every skipped row
        const { maxPageSize, maxOffset, maxPage } = this.config;
        const findings: { field: string; value: string; rule: string; limit?: number }[] = [];

        for (const field of context.fields) {
            const leaf = fieldLeaf(field.name);
            const kind = this.pageSizeFields.has(leaf) ? 'size' : this.offsetFields.has(leaf) ? 'offset' : this.pageFields.has(leaf) ? 'page' : undefined;
            if (!kind || (typeof field.value !== 'number' && typeof field.value !== 'string')) continue;

            const raw = String(field.value).trim();
            // "1e9", "0x7fffffff" and "-1" (often "no limit") are all ways around a naive integer check
            if (!/^\d{1,15}$/.test(raw)) {
                if (/^-|^[+-]?(?:\d+e|0x|inf)/i.test(raw)) {
                    findings.push({ field: clip(field.name, 50), value: clip(raw, 20), rule: `non_plain_${kind}` });
                }
                continue;
            }

            const value = Number(raw);
            if (kind === 'size' && value > maxPageSize) findings.push({ field: clip(field.name, 50), value: raw, rule: 'page_size_too_large', limit: maxPageSize });
            if (kind === 'size' && value === 0) findings.push({ field: clip(field.name, 50), value: raw, rule: 'zero_page_size' }); // "0 = unlimited" in many ORMs
            if (kind === 'offset' && value > maxOffset) findings.push({ field: clip(field.name, 50), value: raw, rule: 'offset_too_deep', limit: maxOffset });
            if (kind === 'page' && value > maxPage) findings.push({ field: clip(field.name, 50), value: raw, rule: 'page_too_deep', limit: maxPage });
        }

        return findings.length > 0 ? violation(this.tool, { findings: findings.slice(0, 10) }) : safe(this.tool);
    }
}
