import { RequestFile } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, safe, violation } from '@tessera/core/static-analysis/shared';

const MAX_REPORTED = 10;

// Hex prefixes of archive formats whose entries carry paths. Tar has no prefix signature.
const ARCHIVE_SIGNATURES = ['504b0304', '504b0506', '504b0708', '1f8b', '377abcaf271c', '526172211a07', '425a68', 'fd377a585a00'];
const ARCHIVE_EXTENSIONS = /\.(?:zip|jar|war|ear|apk|tar|tgz|gz|7z|rar|bz2|xz)$/i;
const ARCHIVE_TYPES = new Set([
    'application/zip', 'application/x-zip-compressed', 'application/java-archive', 'application/x-tar', 'application/gzip',
    'application/x-gzip', 'application/x-7z-compressed', 'application/vnd.rar', 'application/x-rar-compressed',
]);

export default class ZipSlip extends Tool<ToolContextType.File> {
    constructor() {
        super({
            id: 'zip_slip',
            displayName: 'Zip slip',
            category: ToolCategory.Injection,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        if (!ZipSlip.isArchive(context)) {
            return safe(this.tool);
        }

        // Adjust the key names to whatever your normalizer writes into RequestFile.metadata.
        const metadata = (context.metadata ?? {}) as Record<string, unknown>;
        const entries = metadata['entries'];
        if (!Array.isArray(entries)) {
            return failure(this.tool, { filename: clip(context.filename), reason: 'missing_entry_list' });
        }

        const findings: { entry: string; rule: string }[] = [];
        for (const entry of entries) {
            const name = typeof entry === 'string' ? entry : typeof entry === 'object' && entry !== null ? String((entry as Record<string, unknown>)['name'] ?? '') : '';
            const rule = ZipSlip.classify(name) ?? (ZipSlip.isSymlink(entry) ? 'symlink_entry' : undefined);
            if (rule) {
                findings.push({ entry: clip(name, 200), rule });
                if (findings.length >= MAX_REPORTED) break;
            }
        }

        // extraction would write outside the target directory: there is no benign reading of that
        return findings.length > 0 ? violation(this.tool, { filename: clip(context.filename), findings }) : safe(this.tool);
    }

    private static classify(name: string): string | undefined {
        const path = name.replace(/\\/g, '/');
        if (path.includes('\u0000')) return 'null_byte_in_entry';
        if (/^\/|^[a-z]:\//i.test(path) || path.startsWith('//')) return 'absolute_path';
        if (path.split('/').includes('..')) return 'parent_directory_traversal';
        if (/^~\//.test(path)) return 'home_directory_path';
        return undefined;
    }

    // a symlink entry pointing outside the target lets a later entry write through it
    private static isSymlink(entry: unknown): boolean {
        if (typeof entry !== 'object' || entry === null) return false;
        const record = entry as Record<string, unknown>;
        return record['type'] === 'symlink' || record['isSymlink'] === true;
    }

    private static isArchive(file: RequestFile): boolean {
        const hex = typeof file.magicBytes === 'string' ? file.magicBytes.replace(/^0x/i, '').replace(/[\s:]/g, '').toLowerCase() : '';
        const type = String(file.contentType ?? '').split(';')[0].trim().toLowerCase();
        return ARCHIVE_SIGNATURES.some(signature => hex.startsWith(signature))
            || ARCHIVE_TYPES.has(type)
            || ARCHIVE_EXTENSIONS.test(String(file.filename ?? ''));
    }
}
