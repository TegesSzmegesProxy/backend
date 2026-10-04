import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, header, metadataOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

// Fields that must never arrive in a trailer, where some hops merge them into the headers after the fact.
const FORBIDDEN_TRAILERS = new Set([
    'content-length', 'transfer-encoding', 'host', 'authorization', 'cookie', 'content-type', 'content-encoding',
    'te', 'trailer', 'set-cookie', 'x-forwarded-for', 'x-forwarded-host', 'cache-control', 'expect', 'range',
]);

export default class ChunkedEncodingAnomaly extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'chunked_encoding_anomaly'>) {
        super({
            id: 'chunked_encoding_anomaly',
            displayName: 'Chunked encoding anomaly',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        if (!/chunked/i.test(header(context, 'transfer-encoding') ?? '')) {
            return safe(this.tool);
        }

        // chunk framing is consumed by the HTTP parser, so it has to be passed along by that layer.
        // Adjust the key names to whatever your normalizer writes.
        const chunked = metadataOf(context).chunked;
        if (!chunked) {
            return failure(this.tool, { reason: 'chunk_details_unavailable' });
        }

        const { maxChunks, maxChunkSizeDigits, maxExtensionBytes } = this.config;
        const violations: { rule: string; detail?: string }[] = [];
        const suspicions: { rule: string; detail?: string }[] = [];

        const sizes = Array.isArray(chunked.chunkSizes) ? chunked.chunkSizes : [];
        if (sizes.length > maxChunks) violations.push({ rule: 'too_many_chunks', detail: String(sizes.length) });
        for (const size of sizes.slice(0, maxChunks)) {
            const text = String(size);
            if (!/^[0-9a-f]+$/i.test(text)) {
                // "0x5", "-1", " 5", "5 " -- each parser tolerates a different subset
                violations.push({ rule: 'invalid_chunk_size', detail: clip(JSON.stringify(text), 30) });
                break;
            }
            // "0000000000000000000005" is valid hex but parses differently across stacks
            if (text.length > maxChunkSizeDigits) {
                violations.push({ rule: 'oversized_chunk_size_field', detail: String(text.length) });
                break;
            }
        }

        const extensions = Array.isArray(chunked.extensions) ? chunked.extensions.map(String) : [];
        const extensionBytes = extensions.reduce((sum, extension) => sum + extension.length, 0);
        if (extensionBytes > maxExtensionBytes) {
            violations.push({ rule: 'oversized_chunk_extensions', detail: String(extensionBytes) });
        } else if (extensions.some(extension => /[\r\n]/.test(extension))) {
            violations.push({ rule: 'line_break_in_chunk_extension' });
        } else if (extensions.length > 0) {
            // legal, but practically unused by real clients
            suspicions.push({ rule: 'chunk_extensions_present', detail: String(extensions.length) });
        }

        const trailers = Array.isArray(chunked.trailers) ? chunked.trailers.map(name => String(name).toLowerCase().trim()) : [];
        const forbidden = trailers.filter(name => FORBIDDEN_TRAILERS.has(name));
        if (forbidden.length > 0) {
            violations.push({ rule: 'forbidden_trailer_field', detail: forbidden.slice(0, 5).join(',') });
        }

        if (violations.length > 0) return violation(this.tool, { findings: [...violations, ...suspicions] });
        return suspicions.length > 0 ? suspicious(this.tool, { findings: suspicions }) : safe(this.tool);
    }
}
