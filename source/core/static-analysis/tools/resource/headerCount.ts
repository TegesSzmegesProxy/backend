import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, rawHeaderPairs, safe, violation } from '@tessera/core/static-analysis/shared';

export default class HeaderCount extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'header_count'>) {
        super({
            id: 'header_count',
            displayName: 'Header count and size',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // raw pairs keep duplicates; the folded record is the fallback
        const pairs = rawHeaderPairs(context) ?? Object.entries(context.headers ?? {}).map(([name, value]) => [name, String(value)] as [string, string]);

        let total = 0;
        let largest = { name: '', bytes: 0 };
        for (const [name, value] of pairs) {
            const bytes = Buffer.byteLength(name) + Buffer.byteLength(value) + 4; // ": " and CRLF
            total += bytes;
            if (bytes > largest.bytes) largest = { name, bytes };
        }

        const { maxHeaders, maxTotalBytes, maxHeaderBytes } = this.config;
        const reasons: string[] = [];
        if (pairs.length > maxHeaders) reasons.push('too_many_headers');
        if (total > maxTotalBytes) reasons.push('headers_too_large');
        if (largest.bytes > maxHeaderBytes) reasons.push('single_header_too_large');

        return reasons.length > 0
            ? violation(this.tool, {
                reasons,
                count: pairs.length,
                totalBytes: total,
                largest: { name: clip(largest.name, 50), bytes: largest.bytes },
                limits: { maxHeaders, maxTotalBytes, maxHeaderBytes },
            })
            : safe(this.tool);
    }
}
