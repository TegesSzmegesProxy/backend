import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

export default class ArrayUniqueness extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'array_uniqueness'>) {
        super({
            id: 'array_uniqueness',
            displayName: 'Array uniqueness',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        if (typeof context.body !== 'object' || context.body === null || Array.isArray(context.body)) {
            return safe(this.tool);
        }

        const body = context.body as Record<string, unknown>;
        const findings: { property: string; duplicates: number }[] = [];

        for (const name of this.config.properties) {
            const value = Object.prototype.hasOwnProperty.call(body, name) ? body[name] : undefined;
            if (!Array.isArray(value)) continue;

            // compared after normalizing case and whitespace for strings: "SALE10" and " sale10" are one coupon
            const seen = new Set<string>();
            let duplicates = 0;
            for (const item of value) {
                const key = typeof item === 'string' ? `s:${item.trim().toLowerCase()}` : `j:${JSON.stringify(item)}`;
                if (seen.has(key)) duplicates++;
                else seen.add(key);
            }
            if (duplicates > 0) findings.push({ property: clip(name, 50), duplicates });
        }

        // a repeated vote or coupon is the request trying to count twice
        return findings.length > 0 ? violation(this.tool, { endpoint: clip(context.endpoint, 200), findings }) : safe(this.tool);
    }
}
