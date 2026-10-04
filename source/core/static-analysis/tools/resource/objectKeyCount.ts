import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, safe, violation } from '@tessera/core/static-analysis/shared';

export default class ObjectKeyCount extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'object_key_count'>) {
        super({
            id: 'object_key_count',
            displayName: 'Object key count',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // many small objects add up to the same hash-table pressure as one big one, hence maxTotalKeys
        const { maxKeysPerObject, maxTotalKeys } = this.config;
        let total = 0;
        let largest = 0;
        let largestPath = '';

        const stack: { value: unknown; path: string }[] = [{ value: context.body, path: '' }];
        while (stack.length > 0 && total <= maxTotalKeys) {
            const { value, path } = stack.pop()!;
            if (typeof value !== 'object' || value === null) continue;

            if (Array.isArray(value)) {
                value.forEach((item, index) => stack.push({ value: item, path: `${path}[${index}]` }));
                continue;
            }

            const keys = Object.keys(value);
            total += keys.length;
            if (keys.length > largest) {
                largest = keys.length;
                largestPath = path || '(root)';
            }
            for (const key of keys) {
                stack.push({ value: (value as Record<string, unknown>)[key], path: path ? `${path}.${key}` : key });
            }
        }

        const reasons: string[] = [];
        if (largest > maxKeysPerObject) reasons.push('too_many_keys_in_object');
        if (total > maxTotalKeys) reasons.push('too_many_keys_in_total');

        return reasons.length > 0
            ? violation(this.tool, {
                reasons,
                largestObject: { path: largestPath.slice(0, 100), keys: largest },
                totalKeys: total > maxTotalKeys ? `>${maxTotalKeys}` : total,
                maxKeysPerObject,
                maxTotalKeys,
            })
            : safe(this.tool);
    }
}
