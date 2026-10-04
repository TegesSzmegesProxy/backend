import { RequestFile } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

// Extensions a web server or OS may execute. Uploading one is never legitimate for this application.
const EXECUTABLE_EXTENSIONS = new Set([
    'php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phtml', 'phar', 'phps', 'pgif', 'shtml', 'jsp', 'jspx', 'jsw', 'jsv',
    'jspf', 'asp', 'aspx', 'asa', 'asax', 'ascx', 'ashx', 'asmx', 'cer', 'cfm', 'cfc', 'cgi', 'pl', 'py', 'rb', 'sh',
    'bash', 'exe', 'dll', 'com', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'msi',
    'scr', 'jar', 'war', 'elf', 'so', 'htaccess', 'config',
]);

// Names that reconfigure the server when they land in a web root.
const SERVER_CONFIG_NAMES = new Set(['.htaccess', '.htpasswd', 'web.config', '.user.ini', 'php.ini']);

// Hex prefixes of executable or script content.
const EXECUTABLE_SIGNATURES: { name: string; hex: string }[] = [
    { name: 'windows_pe', hex: '4d5a' },
    { name: 'elf', hex: '7f454c46' },
    { name: 'mach_o', hex: 'feedface' },
    { name: 'mach_o', hex: 'feedfacf' },
    { name: 'mach_o', hex: 'cefaedfe' },
    { name: 'mach_o', hex: 'cffaedfe' },
    { name: 'shebang_script', hex: '2321' }, // "#!"
    { name: 'php_script', hex: '3c3f706870' }, // "<?php"
    { name: 'server_page', hex: '3c25' }, // "<%"
];

// Expected content prefixes per image/document extension.
const EXTENSION_SIGNATURES: Record<string, string[]> = {
    jpg: ['ffd8ff'], jpeg: ['ffd8ff'], png: ['89504e47'], gif: ['47494638'], webp: ['52494646'], bmp: ['424d'],
    pdf: ['25504446'], zip: ['504b0304', '504b0506'], gz: ['1f8b'], docx: ['504b0304'], xlsx: ['504b0304'],
};

export default class MaliciousFileUpload extends Tool<ToolContextType.File> {
    constructor() {
        super({
            id: 'malicious_file_upload',
            displayName: 'Malicious file upload',
            category: ToolCategory.Injection,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        const violations: string[] = [];
        const suspicions: string[] = [];

        // "shell.php%00.jpg", "shell.php::$DATA", "shell.php." and "shell.php " all end up as shell.php on disk
        const name = String(context.filename ?? '').replace(/%00.*$|\u0000.*$|::\$data$/i, '').replace(/[.\s]+$/, '').toLowerCase();
        if (name !== String(context.filename ?? '').toLowerCase()) {
            violations.push('filename_truncation_trick');
        }

        const segments = name.split('/').pop()!.split('\\').pop()!.split('.');
        const extension = segments.length > 1 ? segments[segments.length - 1] : '';
        const inner = segments.slice(1, -1);

        if (SERVER_CONFIG_NAMES.has(segments.join('.'))) {
            violations.push('server_configuration_file');
        }
        if (EXECUTABLE_EXTENSIONS.has(extension)) {
            violations.push('executable_extension');
        }
        // "shell.php.jpg": Apache with AddHandler executes any file with .php anywhere in the name
        if (inner.some(part => EXECUTABLE_EXTENSIONS.has(part))) {
            suspicions.push('double_extension');
        }

        const magic = MaliciousFileUpload.hex(context.magicBytes);
        if (magic) {
            const executable = EXECUTABLE_SIGNATURES.find(signature => magic.startsWith(signature.hex));
            if (executable) {
                violations.push(`executable_content:${executable.name}`);
            }
            const expected = EXTENSION_SIGNATURES[extension];
            if (expected && !expected.some(prefix => magic.startsWith(prefix))) {
                suspicions.push('content_does_not_match_extension');
            }
        }

        const evidence = { filename: clip(context.filename), extension, findings: [...violations, ...suspicions] };
        if (violations.length > 0) return violation(this.tool, evidence);
        if (suspicions.length > 0) return suspicious(this.tool, evidence);
        return safe(this.tool);
    }

    // Assumes magicBytes is a hex string; strips "0x", spaces and colons.
    private static hex(magicBytes: string | undefined): string | undefined {
        if (typeof magicBytes !== 'string') return undefined;
        const hex = magicBytes.replace(/^0x/i, '').replace(/[\s:]/g, '').toLowerCase();
        return /^(?:[0-9a-f]{2})+$/.test(hex) ? hex : undefined;
    }
}
