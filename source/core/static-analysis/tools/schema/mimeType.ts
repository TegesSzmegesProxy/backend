import { RequestFile, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// Hex prefixes of file content for each declared type. Types with no fixed signature
// (text/plain, text/csv, application/json) are not listed and are not signature-checked.
const SIGNATURES: Record<string, string[]> = {
    'image/png': ['89504e470d0a1a0a'],
    'image/jpeg': ['ffd8ff'],
    'image/gif': ['474946383761', '474946383961'],
    'image/webp': ['52494646'], // "RIFF"; the "WEBP" marker at bytes 8-11 is checked separately
    'application/pdf': ['25504446'],
};

// Executables and native binaries should never arrive under any allowed type.
const EXECUTABLE_SIGNATURES = [
    '4d5a', // MZ (Windows PE)
    '7f454c46', // ELF
    'cafebabe', // Java class / Mach-O fat binary
];

export default class MimeType extends Tool<ToolContextType.File> {
    private readonly allowedTypes: ReadonlySet<string>;

    constructor(config: ToolConfig<'mime_type'>) {
        super({
            id: 'mime_type',
            displayName: 'MIME type',
            category: ToolCategory.Schema,
            contextType: ToolContextType.File,
        });
        this.allowedTypes = new Set(config.allowedTypes);
    }

    override run(context: RequestFile): ToolResult {
        const declared = context.contentType;

        if (typeof declared !== 'string' || declared.trim() === '') {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: { filename: context.filename, contentType: null, reason: 'missing' },
            };
        }

        // "Text/Plain; charset=UTF-8" -> "text/plain"
        const normalized = declared.split(';')[0].trim().toLowerCase();

        if (!this.allowedTypes.has(normalized)) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: { filename: context.filename, contentType: normalized, reason: 'not_allowed' },
            };
        }

        const magic = MimeType.normalizeMagicBytes(context.magicBytes);
        if (magic !== undefined) {
            if (EXECUTABLE_SIGNATURES.some(signature => magic.startsWith(signature))) {
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'SUSPICIOUS',
                    evidence: { filename: context.filename, contentType: normalized, reason: 'executable_content' },
                };
            }

            if (!MimeType.matchesSignature(normalized, magic)) {
                return {
                    tool: this.tool,
                    status: 'SUCCESS',
                    verdict: 'SUSPICIOUS',
                    evidence: { filename: context.filename, contentType: normalized, reason: 'content_mismatch' },
                };
            }
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    // Assumes magicBytes is a hex string of the file's first bytes; strips "0x", spaces and colons.
    // Returns undefined when absent or not hex, in which case the signature check is skipped.
    private static normalizeMagicBytes(magicBytes: string | undefined): string | undefined {
        if (typeof magicBytes !== 'string') {
            return undefined;
        }
        const hex = magicBytes.replace(/^0x/i, '').replace(/[\s:]/g, '').toLowerCase();
        return /^(?:[0-9a-f]{2})+$/.test(hex) ? hex : undefined;
    }

    private static matchesSignature(mimeType: string, magic: string): boolean {
        const signatures = SIGNATURES[mimeType];
        if (!signatures) {
            return true; // no fixed signature for this type
        }

        if (!signatures.some(signature => magic.startsWith(signature))) {
            return false;
        }

        // WebP is "RIFF" + 4 size bytes + "WEBP"; only verifiable if enough bytes were captured
        if (mimeType === 'image/webp' && magic.length >= 24) {
            return magic.slice(16, 24) === '57454250';
        }

        return true;
    }
}