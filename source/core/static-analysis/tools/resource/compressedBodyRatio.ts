import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, failure, header, metadataOf, safe, violation } from '@tessera/core/static-analysis/shared';

const KNOWN_ENCODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br', 'zstd', 'compress', 'identity']);

export default class CompressedBodyRatio extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'compressed_body_ratio'>) {
        super({
            id: 'compressed_body_ratio',
            displayName: 'Compressed body ratio',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const encodings = (header(context, 'content-encoding') ?? '')
            .split(',')
            .map(encoding => encoding.trim().toLowerCase())
            .filter(encoding => encoding !== '' && encoding !== 'identity');
        if (encodings.length === 0) {
            return safe(this.tool); // body is not compressed
        }

        // "gzip, gzip, gzip, br" stacks bombs inside bombs
        if (encodings.length > this.config.maxEncodings) {
            return violation(this.tool, { reason: 'too_many_encodings', encodings });
        }
        const unknown = encodings.filter(encoding => !KNOWN_ENCODINGS.has(encoding));
        if (unknown.length > 0) {
            return violation(this.tool, { reason: 'unknown_encoding', encodings: unknown.map(encoding => encoding.slice(0, 30)) });
        }

        // the sizes come from whatever layer decompressed the body. Adjust to what your normalizer writes.
        const { compressedBytes, decompressedBytes } = metadataOf(context).compression ?? {};
        const compressed = typeof compressedBytes === 'number' ? compressedBytes : Number(header(context, 'content-length'));
        if (typeof decompressedBytes !== 'number' || !Number.isFinite(compressed) || compressed <= 0) {
            return failure(this.tool, { reason: 'missing_compression_sizes', encodings });
        }

        const ratio = decompressedBytes / compressed;
        const reasons: string[] = [];
        if (decompressedBytes > this.config.maxDecompressedBytes) reasons.push('decompressed_size_too_large');
        // small bodies compress "too well" harmlessly
        if (decompressedBytes >= this.config.minBytesForRatio && ratio > this.config.maxRatio) reasons.push('ratio_too_high');

        return reasons.length > 0
            ? violation(this.tool, { reasons, encodings, compressedBytes: compressed, decompressedBytes, ratio: Math.round(ratio * 10) / 10 })
            : safe(this.tool);
    }
}
