import { NormalizedRequest, RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, isStateChanging, methodOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

interface Finding {
    rule: string;
    field: string;
    value?: number;
}

export default class BusinessLogicTampering extends Tool<ToolContextType.Full> {
    private readonly quantityFields: ReadonlySet<string>;
    private readonly priceFields: ReadonlySet<string>;
    private readonly totalFields: ReadonlySet<string>;
    private readonly percentFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'business_logic_tampering'>) {
        super({
            id: 'business_logic_tampering',
            displayName: 'Business logic tampering',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        this.quantityFields = new Set(config.quantityFields);
        this.priceFields = new Set(config.priceFields);
        this.totalFields = new Set(config.totalFields);
        this.percentFields = new Set(config.percentFields);
    }

    override run(context: NormalizedRequest): ToolResult {
        if (!isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }

        const violations: Finding[] = [];
        const suspicions: Finding[] = [];

        for (const field of context.fields) {
            const leaf = fieldLeaf(field.name);
            const value = BusinessLogicTampering.numberOf(field);
            if (value === undefined) continue;
            const name = clip(field.name);

            if (this.quantityFields.has(leaf)) {
                if (value < 0) violations.push({ rule: 'negative_quantity', field: name, value });
                else if (value === 0) suspicions.push({ rule: 'zero_quantity', field: name });
                else if (!Number.isInteger(value)) suspicions.push({ rule: 'fractional_quantity', field: name, value });
                else if (value > this.config.maxQuantity) suspicions.push({ rule: 'excessive_quantity', field: name, value });
            } else if (this.priceFields.has(leaf) || this.totalFields.has(leaf)) {
                if (value < 0) violations.push({ rule: 'negative_price', field: name, value });
                else if (value === 0) suspicions.push({ rule: 'zero_price', field: name });
            } else if (this.percentFields.has(leaf) && (value < 0 || value > 100)) {
                violations.push({ rule: 'discount_out_of_range', field: name, value });
            }
        }

        const mismatch = this.totalMismatch(context.fields);
        if (mismatch) {
            suspicions.push(mismatch);
        }

        if (violations.length > 0) {
            return violation(this.tool, { findings: [...violations, ...suspicions].slice(0, 10) });
        }
        if (suspicions.length > 0) {
            return suspicious(this.tool, { findings: suspicions.slice(0, 10) });
        }
        return safe(this.tool);
    }

    // A client-supplied total that doesn't add up to its line items ("items.0.price" x "items.0.quantity").
    // Only a total below the line items is reported: discounts lower it, but shipping and tax only add.
    private totalMismatch(fields: RequestField[]): Finding | undefined {
        const totalField = fields.find(field => this.totalFields.has(fieldLeaf(field.name)) && !field.name.includes('.'));
        const total = totalField ? BusinessLogicTampering.numberOf(totalField) : undefined;
        if (!totalField || total === undefined) {
            return undefined;
        }

        // group line-item fields by their parent path: "items.0.price" -> "items.0"
        const lines = new Map<string, { price?: number; quantity?: number }>();
        for (const field of fields) {
            const parent = field.name.includes('.') ? field.name.slice(0, field.name.lastIndexOf('.')) : '';
            if (parent === '') continue;
            const leaf = fieldLeaf(field.name);
            const value = BusinessLogicTampering.numberOf(field);
            if (value === undefined) continue;
            const line = lines.get(parent) ?? {};
            if (leaf === 'price' || leaf === 'unitprice') line.price = value;
            if (this.quantityFields.has(leaf)) line.quantity = value;
            lines.set(parent, line);
        }

        const priced = [...lines.values()].filter(line => line.price !== undefined);
        if (priced.length === 0) {
            return undefined;
        }
        const expected = priced.reduce((sum, line) => sum + line.price! * (line.quantity ?? 1), 0);
        if (total + this.config.totalTolerance < expected) {
            return { rule: 'total_below_line_items', field: clip(totalField.name), value: total };
        }
        return undefined;
    }

    private static numberOf(field: RequestField): number | undefined {
        if (typeof field.value === 'number' && Number.isFinite(field.value)) return field.value;
        if (typeof field.value === 'string' && /^\s*-?\d+(?:\.\d+)?\s*$/.test(field.value)) return Number(field.value);
        return undefined;
    }
}
