import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, safe, violation } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 16_384;

// matchAll clones these, so the g flags are safe on shared constants.
const CARD_CANDIDATE = /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g;
const PESEL_CANDIDATE = /(?<!\d)\d{11}(?!\d)/g;
const SSN_CANDIDATE = /(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)/g;
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g;

export default class PiiInRequest extends Tool<ToolContextType.Field> {
    // identifier type -> fields where it is expected, so finding it there is the point, not a leak
    private readonly expectedFields: ReadonlyMap<string, ReadonlySet<string>>;

    constructor(config: ToolConfig<'pii_in_request'>) {
        super({
            id: 'pii_in_request',
            displayName: 'PII in request',
            category: ToolCategory.DataLeakage,
            contextType: ToolContextType.Field,
        });
        this.expectedFields = new Map(Object.entries(config.expectedFields).map(([type, fields]) => [type, new Set(fields)]));
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' && typeof context.value !== 'number') {
            return safe(this.tool);
        }

        const value = String(context.value).slice(0, MAX_LENGTH);
        const leaf = fieldLeaf(context.name);
        const found: { type: string; masked: string }[] = [];

        const add = (type: string, raw: string): void => {
            if (this.expectedFields.get(type)?.has(leaf)) return;
            const digits = raw.replace(/[\s-]/g, '');
            // the last four characters only, the way receipts print cards
            found.push({ type, masked: `${'*'.repeat(Math.max(0, digits.length - 4))}${digits.slice(-4)}` });
        };

        for (const match of value.matchAll(CARD_CANDIDATE)) {
            const digits = match[0].replace(/[\s-]/g, '');
            if (PiiInRequest.luhn(digits) && /^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35|30[0-5]|36|38)/.test(digits)) add('payment_card', match[0]);
        }
        for (const match of value.matchAll(PESEL_CANDIDATE)) {
            if (PiiInRequest.pesel(match[0])) add('pesel', match[0]);
        }
        for (const match of value.matchAll(SSN_CANDIDATE)) {
            const [area, group, serial] = [match[1], match[2], match[3]];
            if (area !== '000' && area !== '666' && area[0] !== '9' && group !== '00' && serial !== '0000') add('us_ssn', match[0]);
        }
        for (const match of value.toUpperCase().matchAll(IBAN_CANDIDATE)) {
            if (PiiInRequest.iban(match[0])) add('iban', match[0]);
        }

        // checksums make these near-certain, and they don't belong in this field: the field gets stored,
        // logged and shown where card and identity data must not be
        return found.length > 0
            ? violation(this.tool, { name: clip(context.name), location: context.location, found: found.slice(0, 5) })
            : safe(this.tool);
    }

    private static luhn(digits: string): boolean {
        if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
        let sum = 0;
        for (let index = 0; index < digits.length; index++) {
            let digit = Number(digits[digits.length - 1 - index]);
            if (index % 2 === 1) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
        }
        return sum % 10 === 0;
    }

    // Polish national ID: checksum digit and a real birth date (century encoded in the month).
    private static pesel(digits: string): boolean {
        const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
        const sum = weights.reduce((total, weight, index) => total + weight * Number(digits[index]), 0);
        if ((10 - (sum % 10)) % 10 !== Number(digits[10])) return false;

        const encodedMonth = Number(digits.slice(2, 4));
        const centuries: [number, number][] = [[80, 1800], [0, 1900], [20, 2000], [40, 2100], [60, 2200]];
        const century = centuries.find(([offset]) => encodedMonth > offset && encodedMonth <= offset + 12);
        if (!century) return false;
        const year = century[1] + Number(digits.slice(0, 2));
        const month = encodedMonth - century[0];
        const day = Number(digits.slice(4, 6));
        const date = new Date(Date.UTC(year, month - 1, day));
        return date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
    }

    private static iban(candidate: string): boolean {
        const iban = candidate.replace(/\s+/g, '');
        if (iban.length < 15 || iban.length > 34) return false;
        const rearranged = (iban.slice(4) + iban.slice(0, 4)).replace(/[A-Z]/g, letter => String(letter.charCodeAt(0) - 55));
        let remainder = 0;
        for (const digit of rearranged) remainder = (remainder * 10 + Number(digit)) % 97;
        return remainder === 1;
    }
}
