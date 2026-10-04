import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, failure, rawHeaderPairs, safe, violation } from '@tessera/core/static-analysis/shared';

// Headers that must appear at most once. Node keeps only the first Host/Authorization/Content-Type and
// drops the rest, while another hop may use the last one: whoever picks differently can be fooled.
const SINGLE_VALUE = new Set([
    'host', 'authorization', 'proxy-authorization', 'content-type', 'content-length', 'transfer-encoding', 'origin',
    'referer', 'x-forwarded-host', 'x-real-ip', 'x-csrf-token', 'x-xsrf-token', 'x-http-method-override', 'x-api-key',
    'if-modified-since', 'if-unmodified-since', 'user-agent', 'range',
]);

export default class DuplicateHeaders extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'duplicate_headers',
            displayName: 'Duplicate headers',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const pairs = rawHeaderPairs(context);
        if (!pairs) {
            // the folded headers have already lost the duplicates, so this can't be evaluated
            return failure(this.tool, { reason: 'raw_headers_unavailable' });
        }

        const counts = new Map<string, number>();
        for (const [name] of pairs) {
            const lower = name.toLowerCase();
            if (SINGLE_VALUE.has(lower)) counts.set(lower, (counts.get(lower) ?? 0) + 1);
        }

        const duplicated = [...counts].filter(([, count]) => count > 1).map(([name, count]) => ({ header: name, count }));
        return duplicated.length > 0 ? violation(this.tool, { duplicated }) : safe(this.tool);
    }
}
