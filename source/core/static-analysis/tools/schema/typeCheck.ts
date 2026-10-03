import { z } from 'zod';
import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// hard-coded until we have enough infrastructure to support tool configuration
const TYPE_ALIASES: Record<string, string> = {
    int: 'integer',
    float: 'number',
    double: 'number',
    bool: 'boolean',
};

// Locations where the transport only carries text, so "42" is a legitimate integer.
// Adjust to the values RequestField.location actually takes.
const STRING_ENCODED_LOCATIONS = new Set(['query', 'header', 'headers', 'path', 'cookie', 'form']);

// Strict schemas, used everywhere (including JSON bodies).
const STRICT_SCHEMAS: Record<string, z.ZodTypeAny> = {
    string: z.string(),
    integer: z.number().int(),
    number: z.number().finite(),
    boolean: z.boolean(),
    array: z.array(z.unknown()),
    object: z.record(z.string(), z.unknown()),
    null: z.null(),
};

// Text-encoded schemas, used in addition to the strict ones in STRING_ENCODED_LOCATIONS.
// Deliberately not z.coerce.*: coerce turns "" and null into 0 and any non-empty string into true.
const STRING_ENCODED_SCHEMAS: Record<string, z.ZodTypeAny> = {
    integer: z.string().trim().regex(/^-?\d+$/),
    number: z.string().trim().min(1).refine(value => Number.isFinite(Number(value))),
    boolean: z.string().trim().regex(/^(?:true|false)$/i),
};

export default class TypeCheck extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'zod_type_check',
            displayName: 'Type check (Zod)',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const declared = typeof context.type === 'string' ? context.type.trim().toLowerCase() : '';
        const expected = TYPE_ALIASES[declared] ?? declared;
        const strict = STRICT_SCHEMAS[expected];

        // a declared type we don't know can't be evaluated, which is different from "safe"
        if (!strict) {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { name: context.name, declaredType: String(context.type).slice(0, 50), reason: 'unsupported_type' },
            };
        }

        const strictResult = strict.safeParse(context.value);
        if (strictResult.success) {
            return TypeCheck.safe(this.tool);
        }

        const encoded = STRING_ENCODED_SCHEMAS[expected];
        if (encoded && STRING_ENCODED_LOCATIONS.has(String(context.location).toLowerCase())) {
            if (encoded.safeParse(context.value).success) {
                return TypeCheck.safe(this.tool);
            }
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'POLICY_VIOLATION',
            evidence: {
                name: context.name,
                location: context.location,
                declaredType: expected,
                // code + message only: zod issues can embed the received value in other fields
                issues: strictResult.error.issues.slice(0, 5).map(issue => ({ code: issue.code, message: issue.message })),
            },
        };
    }

    private static safe(tool: string): ToolResult {
        return {
            tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}