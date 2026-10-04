import { RequestFile } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, safe, suspicious } from '@tessera/core/static-analysis/shared';

const MAX_SCAN = 1024 * 1024;

// File formats identified by their first bytes (as latin1 text, so every byte maps to one character).
const FORMATS: { name: string; prefix: string }[] = [
    { name: 'gif', prefix: 'GIF87a' },
    { name: 'gif', prefix: 'GIF89a' },
    { name: 'png', prefix: '\x89PNG\r\n\x1a\n' },
    { name: 'jpeg', prefix: '\xff\xd8\xff' },
    { name: 'pdf', prefix: '%PDF-' },
    { name: 'bmp', prefix: 'BM' },
    { name: 'zip', prefix: 'PK\x03\x04' },
];

// Content that makes the same bytes meaningful to a second interpreter.
const SECOND_FORMATS: { name: string; pattern: RegExp }[] = [
    { name: 'html_or_script', pattern: /<\s*(?:script|html|body|iframe|svg|object|embed)\b|<\s*img[^>]+onerror\s*=/i },
    { name: 'php', pattern: /<\?(?:php|=)/i },
    { name: 'server_page', pattern: /<%[=@!]?\s*\w/ },
    { name: 'javascript_statement', pattern: /\b(?:alert|eval|fetch|document\.cookie|window\.location|import\s*\()\s*[(.=]/ },
    { name: 'pdf_javascript', pattern: /\/(?:JavaScript|JS|OpenAction|Launch|EmbeddedFile)\b/ },
];

export default class PolyglotFile extends Tool<ToolContextType.File> {
    constructor() {
        super({
            id: 'polyglot_file',
            displayName: 'Polyglot file',
            category: ToolCategory.Injection,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        const content = PolyglotFile.content(context);
        if (content === undefined) {
            // needs the file's bytes; without them the file can't be evaluated, which is different from "safe"
            return failure(this.tool, { filename: clip(context.filename), reason: 'missing_content' });
        }

        const format = FORMATS.find(candidate => content.startsWith(candidate.prefix))?.name;
        if (!format) {
            return safe(this.tool); // not a binary container another format could hide in
        }

        const findings: string[] = [];

        // GIF89a/*...*/=alert(1)//  -- the header itself opens a JS comment or assignment
        if (format === 'gif' && /^GIF8[79]a\s*(?:\/\*|=)/.test(content)) {
            findings.push('gif_javascript_header');
        }

        // skip the header so a format's own magic can't match itself
        const body = content.slice(8, MAX_SCAN);
        for (const second of SECOND_FORMATS) {
            if (format === 'pdf' && second.name === 'javascript_statement') continue; // covered by pdf_javascript
            if (format !== 'pdf' && second.name === 'pdf_javascript') continue;
            if (second.pattern.test(body)) findings.push(second.name);
        }

        // an archive appended after an image (GIFAR, JAR-in-JPEG)
        if (format !== 'zip' && body.includes('PK\x03\x04')) {
            findings.push('embedded_archive');
        }

        return findings.length > 0
            ? suspicious(this.tool, { filename: clip(context.filename), format, findings })
            : safe(this.tool);
    }

    // The file's leading bytes as latin1 text: metadata.content (text or base64) when the normalizer
    // provides it, otherwise the magic bytes. Adjust the key names to whatever your normalizer writes.
    private static content(file: RequestFile): string | undefined {
        const metadata = (file.metadata ?? {}) as Record<string, unknown>;
        if (typeof metadata['contentBase64'] === 'string') {
            return Buffer.from(metadata['contentBase64'], 'base64').toString('latin1');
        }
        if (typeof metadata['content'] === 'string') {
            return metadata['content'];
        }
        if (typeof file.magicBytes === 'string') {
            const hex = file.magicBytes.replace(/^0x/i, '').replace(/[\s:]/g, '');
            if (/^(?:[0-9a-f]{2})+$/i.test(hex)) return Buffer.from(hex, 'hex').toString('latin1');
        }
        return undefined;
    }
}
