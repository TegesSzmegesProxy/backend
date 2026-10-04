import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

interface WebshellRule {
    name: string;
    pattern: RegExp;
}

const MAX_SCAN = 1024 * 1024;

// The regex sources are stored base64-encoded: written out in plain text they are themselves webshell
// signatures, and endpoint antivirus quarantines this source file. Decode one to read or edit it:
//   Buffer.from('<encoded>', 'base64').toString()
const ENCODED_RULES: { name: string; encoded: string }[] = [
    // eval/assert/system(... $_POST[...])   -- China Chopper and PHP one-liners
    { name: 'php_eval_of_request', encoded: 'XGIoPzpldmFsfGFzc2VydHxzeXN0ZW18cGFzc3RocnV8c2hlbGxfZXhlY3xleGVjfHBvcGVufHByb2Nfb3BlbilccypcKFxzKig/OkBccyopPyg/OnN0cmlwc2xhc2hlc1xzKlwoXHMqKT9cJF8oPzpHRVR8UE9TVHxSRVFVRVNUfENPT0tJRXxTRVJWRVJ8RklMRVMpXGI=' },
    // eval(base64_decode(...)), eval(gzinflate(str_rot13(...)))
    { name: 'php_obfuscated_eval', encoded: 'XGIoPzpldmFsfGFzc2VydClccypcKFxzKig/OkBccyopPyg/OmJhc2U2NF9kZWNvZGV8Z3ppbmZsYXRlfGd6dW5jb21wcmVzc3xnemRlY29kZXxzdHJfcm90MTN8c3RycmV2fGhleDJiaW58Y29udmVydF91dWRlY29kZSlccypcKA==' },
    // $_GET['f']($_GET['x'])   -- calling a function whose name comes from the request
    { name: 'php_variable_function', encoded: 'XCRfKD86R0VUfFBPU1R8UkVRVUVTVHxDT09LSUUpXHMqXFtccypbJyJdP1x3K1snIl0/XHMqXF1ccypcKFxzKlwkXyg/OkdFVHxQT1NUfFJFUVVFU1R8Q09PS0lFKQ==' },
    // well-known shell families by name or marker string (c99, r57, WSO, b374k, weevely, ...)
    { name: 'known_webshell_family', encoded: 'XGIoPzpjOTlzaGVsbHxjOTlffHI1N3NoZWxsfFdTT1xzK1xkfEZpbGVzTWFufGIzNzRrfHdlZXZlbHl8cDB3bnl8QW5vbnltb3VzRm94fEluZG9YcGxvaXR8QWxmYVxzKlNoZWxsfG1hcmlqdWFuYVxzK3NoZWxsfGFudFN3b3JkfEJlaGluZGVyfEdvZHppbGxhKVxi' },
    // eval(Request.Item["x"], "unsafe")   -- ASPX chopper
    { name: 'aspx_eval_of_request', encoded: 'ZXZhbFxzKlwoXHMqUmVxdWVzdCg/OlwuSXRlbSk/XHMqW1soXVxzKlsiJ11cdytbIiddXHMqW1xdKV1ccyooPzosXHMqWyInXXVuc2FmZVsiJ10pPw==' },
    // Runtime.getRuntime().exec(request.getParameter(...))   -- JSP shells
    { name: 'jsp_exec_of_request', encoded: 'UnVudGltZVxzKlwuXHMqZ2V0UnVudGltZVxzKlwoXHMqXClccypcLlxzKmV4ZWNccypcKFxzKnJlcXVlc3RccypcLlxzKmdldFBhcmFtZXRlclxzKlwo' },
    // new ProcessBuilder(... request.getParameter ...), "cmd", "/c", request...
    { name: 'process_from_request', encoded: 'bmV3XHMrUHJvY2Vzc0J1aWxkZXJccypcKFteKV0qcmVxdWVzdFxzKlwuXHMqZ2V0UGFyYW1ldGVyfFsiJ11jbWQoPzpcLmV4ZSk/WyInXVxzKixccypbIiddXC9jWyInXVxzKixccypyZXF1ZXN0' },
];

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: WebshellRule[] = ENCODED_RULES.map(({ name, encoded }) => ({
    name,
    pattern: new RegExp(Buffer.from(encoded, 'base64').toString('utf8'), 'i'),
}));

export default class WebshellSignature extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'webshell_signature',
            displayName: 'Webshell signature',
            category: ToolCategory.Injection,
            // Full context: shells arrive both as uploads (file content) and inside request bodies
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const fileFindings: { source: string; rules: string[] }[] = [];
        const fieldFindings: { source: string; rules: string[] }[] = [];

        for (const file of context.files) {
            // Adjust the key names to whatever your normalizer writes into RequestFile.metadata.
            const metadata = (file.metadata ?? {}) as Record<string, unknown>;
            const content = typeof metadata['content'] === 'string'
                ? metadata['content']
                : typeof metadata['contentBase64'] === 'string' ? Buffer.from(metadata['contentBase64'], 'base64').toString('latin1') : undefined;
            if (content === undefined) continue;
            const rules = WebshellSignature.match(content.slice(0, MAX_SCAN));
            if (rules.length > 0) fileFindings.push({ source: `file:${clip(file.filename, 100)}`, rules });
        }

        for (const field of context.fields) {
            if (typeof field.value !== 'string') continue;
            const rules = WebshellSignature.match(field.value.slice(0, MAX_SCAN));
            if (rules.length > 0) fieldFindings.push({ source: `${field.location}:${clip(field.name, 50)}`, rules });
        }

        // An uploaded file with a shell signature is about to be stored on the server: a violation.
        // The same text in a field might be a developer pasting code into a support ticket: suspicious.
        if (fileFindings.length > 0) {
            return violation(this.tool, { findings: [...fileFindings, ...fieldFindings].slice(0, 10) });
        }
        return fieldFindings.length > 0 ? suspicious(this.tool, { findings: fieldFindings.slice(0, 10) }) : safe(this.tool);
    }

    private static match(text: string): string[] {
        return RULES.filter(rule => rule.pattern.test(text)).map(rule => rule.name);
    }
}
