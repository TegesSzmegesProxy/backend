import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, safe, violation } from '@tessera/core/static-analysis/shared';

type Operator = '<' | '>' | '<=' | '>=';

interface Rule {
    operator: Operator;
    length: number;
}

const COMPARE: Record<Operator, (length: number, limit: number) => boolean> = {
    '<': (length, limit) => length < limit,
    '>': (length, limit) => length > limit,
    '<=': (length, limit) => length <= limit,
    '>=': (length, limit) => length >= limit,
};

export default class StringLength extends Tool<ToolContextType.Field> {
    // the comparisons a string's length must satisfy
    private readonly rules: Rule[];

    constructor (config: ToolConfig<'string_length'>) {
        super({
            id: 'string_length',
            displayName: 'String length',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
        this.rules = 'operator' in config ? [config] : StringLength.fromBounds(config);
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const length = context.value.length;
        const broken = this.rules.find(rule => !COMPARE[rule.operator](length, rule.length));
        return broken
            ? violation(this.tool, { length, required: `length ${broken.operator} ${broken.length}` })
            : safe(this.tool);
    }

    // The tessera.tools/v1 form: inclusive minimum and/or maximum.
    private static fromBounds(config: { minLength?: number; maxLength?: number }): Rule[] {
        const rules: Rule[] = [];
        if (config.minLength !== undefined) rules.push({ operator: '>=', length: config.minLength });
        if (config.maxLength !== undefined) rules.push({ operator: '<=', length: config.maxLength });
        return rules;
    }
}
