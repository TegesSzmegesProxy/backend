import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, safe, violation } from '@tessera/core/static-analysis/shared';

export default class ArrayLength extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'array_length'>) {
        super({
            id: 'array_length',
            displayName: 'Array length',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const { maxArrayLength, maxTotalElements } = this.config;
        const oversized: { path: string; length: number }[] = [];
        let total = 0;

        const stack: { value: unknown; path: string }[] = [{ value: context.body, path: '' }];
        while (stack.length > 0 && total <= maxTotalElements) {
            const { value, path } = stack.pop()!;
            if (typeof value !== 'object' || value === null) continue;

            if (Array.isArray(value)) {
                total += value.length;
                if (value.length > maxArrayLength) {
                    oversized.push({ path: (path || '(root)').slice(0, 100), length: value.length });
                    continue; // no need to walk into an array that already fails
                }
                value.forEach((item, index) => stack.push({ value: item, path: `${path}[${index}]` }));
            } else {
                for (const [key, child] of Object.entries(value)) {
                    stack.push({ value: child, path: path ? `${path}.${key}` : key });
                }
            }
        }

        if (oversized.length > 0 || total > maxTotalElements) {
            return violation(this.tool, {
                oversized: oversized.slice(0, 5),
                totalElements: total > maxTotalElements ? `>${maxTotalElements}` : total,
                maxArrayLength,
                maxTotalElements,
            });
        }
        return safe(this.tool);
    }
}
