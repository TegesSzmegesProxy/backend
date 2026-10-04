import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

type Format = ToolConfig<'format_validation'>['format'];

// IBAN length per country (subset).
const IBAN_LENGTHS: Record<string, number> = {
    PL: 28, DE: 22, GB: 22, FR: 27, ES: 24, IT: 27, NL: 18, BE: 16, CZ: 24, SK: 24, AT: 20, CH: 21, IE: 22, SE: 24,
    NO: 15, DK: 18, FI: 18, PT: 25, LT: 20, LV: 21, EE: 20, UA: 29,
};

const VALIDATORS: Record<Format, (value: string) => boolean> = {
    // pragmatic, not full RFC 5322: one @, a dotted domain, no spaces or control characters
    email: value => value.length <= 254 && /^[^\s@\x00-\x1f"<>()[\]\\,;:]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value),
    uuid: value => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value),
    date: value => {
        const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
        if (!match) return false;
        const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
        return date.getUTCFullYear() === Number(match[1]) && date.getUTCMonth() === Number(match[2]) - 1 && date.getUTCDate() === Number(match[3]);
    },
    datetime: value => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value)),
    // E.164-ish: optional +, 7-15 digits, spaces/dashes/parentheses allowed between them
    phone: value => /^\+?[\d\s().-]{7,25}$/.test(value) && /^\d{7,15}$/.test(value.replace(/\D/g, '')),
    iban: value => {
        const iban = value.replace(/\s+/g, '').toUpperCase();
        const expected = IBAN_LENGTHS[iban.slice(0, 2)];
        if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(iban) || (expected !== undefined && iban.length !== expected)) return false;
        const rearranged = (iban.slice(4) + iban.slice(0, 4)).replace(/[A-Z]/g, letter => String(letter.charCodeAt(0) - 55));
        let remainder = 0;
        for (const digit of rearranged) remainder = (remainder * 10 + Number(digit)) % 97;
        return remainder === 1;
    },
    uri: value => {
        try {
            const url = new URL(value);
            return (url.protocol === 'http:' || url.protocol === 'https:') && url.hostname !== '';
        } catch {
            return false;
        }
    },
    postalcode: value => /^[A-Za-z0-9][A-Za-z0-9 -]{1,8}[A-Za-z0-9]$/.test(value),
    currency: value => /^[A-Z]{3}$/.test(value),
};

export default class FormatValidation extends Tool<ToolContextType.Field> {
    constructor(private readonly config: ToolConfig<'format_validation'>) {
        super({
            id: 'format_validation',
            displayName: 'Format validation',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const { format } = this.config;
        if (typeof context.value !== 'string') {
            return safe(this.tool); // a non-string is TypeCheck's concern
        }

        return VALIDATORS[format](context.value.trim())
            // the value is not echoed back: formats like IBAN and phone are personal data
            ? safe(this.tool)
            : violation(this.tool, { name: clip(context.name), location: context.location, format, length: context.value.length });
    }
}
