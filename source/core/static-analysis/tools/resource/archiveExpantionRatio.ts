import { RequestFile, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// Hex prefixes of the file's first bytes. Tar has no prefix signature (its marker is at offset 257).
const ARCHIVE_SIGNATURES = [
    '504b0304', // zip
    '504b0506', // zip (empty)
    '504b0708', // zip (spanned)
    '1f8b', // gzip
    '425a68', // bzip2
    'fd377a585a00', // xz
    '28b52ffd', // zstd
    '377abcaf271c', // 7z
    '526172211a07', // rar
];

const ARCHIVE_CONTENT_TYPES = new Set([
    'application/zip',
    'application/x-zip-compressed',
    'application/gzip',
    'application/x-gzip',
    'application/x-bzip2',
    'application/x-xz',
    'application/zstd',
    'application/x-7z-compressed',
    'application/vnd.rar',
    'application/x-rar-compressed',
    'application/x-tar',
]);

export default class ArchiveExpansionRatio extends Tool<ToolContextType.File> {
    constructor(private readonly config: ToolConfig<'archive_expansion_ratio'>) {
        super({
            id: 'archive_expansion_ratio',
            displayName: 'Archive expansion ratio',
            category: ToolCategory.Resource,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        if (!ArchiveExpansionRatio.isArchive(context)) {
            return ArchiveExpansionRatio.safe(this.tool);
        }

        // Adjust the key names to whatever your normalizer writes into RequestFile.metadata.
        const metadata = (context.metadata ?? {}) as Record<string, unknown>;
        const uncompressed = metadata['uncompressedSize'];
        const entries = metadata['entryCount'];

        if (!ArchiveExpansionRatio.isNonNegativeNumber(uncompressed)) {
            return ArchiveExpansionRatio.error(this.tool, context, 'missing_uncompressed_size');
        }
        if (!ArchiveExpansionRatio.isNonNegativeNumber(context.size) || context.size === 0) {
            return ArchiveExpansionRatio.error(this.tool, context, 'invalid_size');
        }

        const ratio = uncompressed / context.size;
        const { maxUncompressedBytes, minBytesForRatio, maxRatio, maxEntries } = this.config;
        const reasons: string[] = [];

        if (uncompressed > maxUncompressedBytes) {
            reasons.push('uncompressed_size_too_large');
        }
        // below minBytesForRatio, tiny archives compress "badly" harmlessly
        if (uncompressed >= minBytesForRatio && ratio > maxRatio) {
            reasons.push('ratio_too_high');
        }
        if (ArchiveExpansionRatio.isNonNegativeNumber(entries) && entries > maxEntries) {
            reasons.push('too_many_entries');
        }

        if (reasons.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: {
                    filename: String(context.filename).slice(0, 100),
                    size: context.size,
                    uncompressedSize: uncompressed,
                    ratio: Math.round(ratio * 10) / 10,
                    entryCount: ArchiveExpansionRatio.isNonNegativeNumber(entries) ? entries : undefined,
                    reasons,
                },
            };
        }

        return ArchiveExpansionRatio.safe(this.tool);
    }

    private static isArchive(file: RequestFile): boolean {
        if (typeof file.magicBytes === 'string') {
            // assumes a hex string; strips "0x", spaces and colons
            const hex = file.magicBytes.replace(/^0x/i, '').replace(/[\s:]/g, '').toLowerCase();
            if (ARCHIVE_SIGNATURES.some(signature => hex.startsWith(signature))) {
                return true;
            }
        }

        const declared = typeof file.contentType === 'string' ? file.contentType.split(';')[0].trim().toLowerCase() : '';
        return ARCHIVE_CONTENT_TYPES.has(declared);
    }

    private static isNonNegativeNumber(value: unknown): value is number {
        return typeof value === 'number' && Number.isFinite(value) && value >= 0;
    }

    private static error(tool: string, file: RequestFile, reason: string): ToolResult {
        return {
            tool,
            status: 'ERROR',
            verdict: 'ERROR',
            evidence: { filename: String(file.filename).slice(0, 100), reason },
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