import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, metadataOf, safe, violation } from '@tessera/core/static-analysis/shared';

const MAX_RAW_SCAN = 1024 * 1024;

export default class JsonDepth extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'json_depth'>) {
        super({
            id: 'json_depth',
            displayName: 'JSON nesting depth',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // The raw body shows the nesting even when a parser gave up on it; the parsed body is the fallback.
        const raw = metadataOf(context).rawBody;
        const { maxDepth } = this.config;
        // counting stops far over the limit, so a hostile body can't keep us busy
        const cap = maxDepth * 10;
        const depth = typeof raw === 'string' ? JsonDepth.rawDepth(raw, cap) : JsonDepth.parsedDepth(context.body, cap);

        if (depth > maxDepth) {
            return violation(this.tool, { depth: depth > cap ? `>${cap}` : depth, maxDepth });
        }
        return safe(this.tool);
    }

    // Counts bracket nesting outside strings, without recursion, so a hostile body can't exhaust our stack.
    private static rawDepth(raw: string, cap: number): number {
        let depth = 0;
        let max = 0;
        let inString = false;
        const end = Math.min(raw.length, MAX_RAW_SCAN);
        for (let index = 0; index < end; index++) {
            const char = raw[index];
            if (inString) {
                if (char === '\\') index++;
                else if (char === '"') inString = false;
            } else if (char === '"') {
                inString = true;
            } else if (char === '{' || char === '[') {
                max = Math.max(max, ++depth);
                if (max > cap) break; // already far over the limit
            } else if (char === '}' || char === ']') {
                depth = Math.max(0, depth - 1);
            }
        }
        return max;
    }

    // Iterative walk of an already-parsed body.
    private static parsedDepth(body: unknown, cap: number): number {
        let max = 0;
        const stack: { value: unknown; depth: number }[] = [{ value: body, depth: 0 }];
        let visited = 0;
        while (stack.length > 0 && visited++ < 100_000) {
            const { value, depth } = stack.pop()!;
            if (typeof value !== 'object' || value === null) continue;
            max = Math.max(max, depth + 1);
            if (max > cap) break;
            for (const child of Array.isArray(value) ? value : Object.values(value)) {
                stack.push({ value: child, depth: depth + 1 });
            }
        }
        return max;
    }
}
