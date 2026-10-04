import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, headerValues, metadataOf, rawHeaderPairs, safe, violation } from '@tessera/core/static-analysis/shared';

export default class RequestSmuggling extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'request_smuggling',
            displayName: 'Request smuggling',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // Node rejects the crudest forms itself; this catches what it lets through and what a front proxy
        // may parse differently. Raw headers keep duplicates the folded record would hide.
        const contentLengths = headerValues(context, 'content-length');
        const transferEncodings = headerValues(context, 'transfer-encoding');
        const findings: { rule: string; detail?: string }[] = [];

        if (contentLengths.length > 0 && transferEncodings.length > 0) {
            findings.push({ rule: 'content_length_with_transfer_encoding' });
        }

        // "Content-Length: 5, 6" (folded duplicates) or two Content-Length headers
        const lengths = contentLengths.flatMap(value => value.split(',')).map(value => value.trim());
        if (lengths.length > 1) {
            findings.push({ rule: new Set(lengths).size > 1 ? 'conflicting_content_lengths' : 'duplicate_content_length' });
        }
        const invalid = lengths.find(value => !/^\d{1,15}$/.test(value));
        if (invalid !== undefined) {
            findings.push({ rule: 'invalid_content_length', detail: clip(invalid, 30) });
        }

        if (transferEncodings.length > 1) {
            findings.push({ rule: 'duplicate_transfer_encoding' });
        }
        for (const value of transferEncodings) {
            // only "chunked", optionally after real codings, is unambiguous; "xchunked", "chunked " with
            // odd whitespace, "chunked, identity" or a quoted value are classic TE obfuscations
            const codings = value.split(',').map(coding => coding.trim().toLowerCase());
            const last = codings[codings.length - 1];
            if (last !== 'chunked' || codings.slice(0, -1).some(coding => !['gzip', 'deflate', 'br', 'compress', 'x-gzip'].includes(coding))
                || /[\t\v\f\u0000-\u001f"]/.test(value) || value !== value.trim()) {
                findings.push({ rule: 'obfuscated_transfer_encoding', detail: JSON.stringify(clip(value, 50)) });
            }
        }

        // header names a front-end may not recognise as Transfer-Encoding / Content-Length
        for (const [name] of rawHeaderPairs(context) ?? []) {
            const lower = name.toLowerCase();
            if (lower !== 'transfer-encoding' && lower !== 'content-length' && /^(?:transfer[-_ ]?encoding|content[-_ ]?length)\s*$/i.test(name.replace(/[^\w -]/g, ''))) {
                findings.push({ rule: 'lookalike_framing_header', detail: clip(name, 50) });
            }
        }

        if (transferEncodings.length > 0 && metadataOf(context).httpVersion === '1.0') {
            findings.push({ rule: 'transfer_encoding_on_http_1_0' });
        }

        // any framing ambiguity is rejected: no legitimate client needs one
        return findings.length > 0 ? violation(this.tool, { findings }) : safe(this.tool);
    }
}
