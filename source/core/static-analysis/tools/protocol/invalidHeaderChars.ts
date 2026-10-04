import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, rawHeaderPairs, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

// RFC 9110 token characters; anything else in a header name is invalid.
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export default class InvalidHeaderChars extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'invalid_header_chars',
            displayName: 'Invalid header characters',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const pairs = rawHeaderPairs(context) ?? Object.entries(context.headers ?? {}).map(([name, value]) => [name, String(value)] as [string, string]);
        const violations: { header: string; rule: string }[] = [];
        const suspicions: { header: string; rule: string }[] = [];

        for (const [name, value] of pairs) {
            const label = clip(JSON.stringify(name), 60);
            if (/\s$/.test(name)) violations.push({ header: label, rule: 'whitespace_before_colon' });
            else if (!TOKEN.test(name)) violations.push({ header: label, rule: 'invalid_name_character' });

            // obs-fold: a value continued on the next line, deprecated and parsed inconsistently
            if (/\r?\n[ \t]/.test(value)) violations.push({ header: label, rule: 'obsolete_line_folding' });
            else if (/[\r\n]/.test(value)) violations.push({ header: label, rule: 'line_break_in_value' });
            if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(value.replace(/\r?\n[ \t]/g, ''))) violations.push({ header: label, rule: 'control_character_in_value' });
            // bytes above 0x7e are "obs-text": tolerated, but no modern client needs them
            if (/[\u0080-￿]/.test(value)) suspicions.push({ header: label, rule: 'non_ascii_value' });
        }

        if (violations.length > 0) return violation(this.tool, { findings: [...violations, ...suspicions].slice(0, 10) });
        return suspicions.length > 0 ? suspicious(this.tool, { findings: suspicions.slice(0, 10) }) : safe(this.tool);
    }
}
