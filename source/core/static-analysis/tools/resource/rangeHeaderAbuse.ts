import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

interface ByteRange {
    start: number;
    end: number; // inclusive; Infinity for "500-"
}

export default class RangeHeaderAbuse extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'range_header_abuse'>) {
        super({
            id: 'range_header_abuse',
            displayName: 'Range header abuse',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const value = header(context, 'range');
        if (value === undefined) {
            return safe(this.tool);
        }
        if (value.length > this.config.maxHeaderLength) {
            return violation(this.tool, { reason: 'range_header_too_long', length: value.length });
        }

        const match = value.match(/^\s*([a-z]+)\s*=\s*(.+)$/i);
        if (!match || match[1].toLowerCase() !== 'bytes') {
            return suspicious(this.tool, { reason: 'malformed_range_header', value: clip(value) });
        }

        const ranges: ByteRange[] = [];
        for (const spec of match[2].split(',')) {
            const part = spec.trim();
            const parsed = part.match(/^(\d*)\s*-\s*(\d*)$/);
            if (!parsed || (parsed[1] === '' && parsed[2] === '')) {
                return suspicious(this.tool, { reason: 'malformed_range', range: clip(part, 50) });
            }
            // "-500" is the last 500 bytes; its position is unknown without the length, so treat it as the tail
            const range = parsed[1] === ''
                ? { start: Number.MAX_SAFE_INTEGER - Number(parsed[2]), end: Infinity }
                : { start: Number(parsed[1]), end: parsed[2] === '' ? Infinity : Number(parsed[2]) };
            if (range.end < range.start) {
                return suspicious(this.tool, { reason: 'inverted_range', range: clip(part, 50) });
            }
            ranges.push(range);
        }

        if (ranges.length > this.config.maxRanges) {
            return violation(this.tool, { reason: 'too_many_ranges', ranges: ranges.length, limit: this.config.maxRanges });
        }
        // overlapping ranges make the server send the same bytes again and again (Apache Killer, CVE-2011-3192)
        const sorted = [...ranges].sort((a, b) => a.start - b.start);
        for (let index = 1; index < sorted.length; index++) {
            if (sorted[index].start <= sorted[index - 1].end) {
                return violation(this.tool, { reason: 'overlapping_ranges', ranges: ranges.length });
            }
        }

        return safe(this.tool);
    }
}
