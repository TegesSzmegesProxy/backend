import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 8192;
const MAX_FINDINGS = 10;

// Runs of %XX escapes, or of \xXX escapes as used in JSON/source-style payloads. matchAll clones the regex.
const ESCAPED_BYTES = /(?:%[0-9a-f]{2})+|(?:\\x[0-9a-f]{2})+/gi;

export default class OverlongUtf8 extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'overlong_utf8',
            displayName: 'Overlong UTF-8',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const findings: { rule: string; bytes: string }[] = [];
        for (const match of context.value.slice(0, MAX_LENGTH).matchAll(ESCAPED_BYTES)) {
            const bytes = match[0].split(/%|\\x/i).filter(Boolean).map(hex => parseInt(hex, 16));
            for (const finding of OverlongUtf8.validate(bytes)) {
                if (findings.length >= MAX_FINDINGS) break;
                findings.push({ rule: finding.rule, bytes: finding.bytes.map(byte => byte.toString(16).padStart(2, '0')).join(' ') });
            }
        }

        if (findings.length === 0) {
            return safe(this.tool);
        }

        const evidence = { name: clip(context.name), location: context.location, findings };
        // Overlong forms and encoded surrogates are forbidden by RFC 3629 and only ever used to sneak characters
        // past filters. Other invalid bytes are often just Latin-1 text (%e9 for "é"), so they are only suspicious.
        return findings.some(finding => finding.rule === 'overlong_encoding' || finding.rule === 'surrogate_code_point')
            ? violation(this.tool, evidence)
            : suspicious(this.tool, evidence);
    }

    // Walks a byte sequence as UTF-8 and reports each invalid sequence.
    private static validate(bytes: number[]): { rule: string; bytes: number[] }[] {
        const findings: { rule: string; bytes: number[] }[] = [];
        let index = 0;

        while (index < bytes.length) {
            const lead = bytes[index];
            if (lead < 0x80) {
                index++;
                continue;
            }

            let length = 0;
            if (lead >= 0xc0 && lead <= 0xdf) length = 2;
            else if (lead >= 0xe0 && lead <= 0xef) length = 3;
            else if (lead >= 0xf0 && lead <= 0xf7) length = 4;

            if (length === 0) {
                findings.push({ rule: lead < 0xc0 ? 'unexpected_continuation_byte' : 'invalid_lead_byte', bytes: [lead] });
                index++;
                continue;
            }

            const sequence = bytes.slice(index, index + length);
            if (sequence.length < length || sequence.slice(1).some(byte => (byte & 0xc0) !== 0x80)) {
                findings.push({ rule: 'truncated_sequence', bytes: sequence });
                index++;
                continue;
            }

            const second = sequence[1];
            if (lead === 0xc0 || lead === 0xc1 || (lead === 0xe0 && second < 0xa0) || (lead === 0xf0 && second < 0x90)) {
                findings.push({ rule: 'overlong_encoding', bytes: sequence });
            } else if (lead === 0xed && second >= 0xa0) {
                findings.push({ rule: 'surrogate_code_point', bytes: sequence });
            } else if (lead > 0xf4 || (lead === 0xf4 && second >= 0x90)) {
                findings.push({ rule: 'beyond_unicode_range', bytes: sequence });
            }
            index += length;
        }

        return findings;
    }
}
