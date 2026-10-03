import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// hard-coded until we have enough infrastructure to support tool configuration
const MAX_LENGTH = 2048;
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

// Declared field types this tool applies to. Adjust to the vocabulary your normalizer uses.
const URL_TYPES = new Set(['url', 'uri']);

// Require an explicit "scheme://" up front. The WHATWG parser is lenient and also accepts
// "http:example.com" and "http:\\example.com", which most consumers would not treat as valid.
const EXPLICIT_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

// Whitespace and control characters, which the parser silently strips or rewrites.
const FORBIDDEN_CHARS = /[\u0000-\u0020\u007f-\u009f]/;

export default class UrlValidator extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'url_validator',
            displayName: 'URL validator',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const declared = typeof context.type === 'string' ? context.type.trim().toLowerCase() : '';

        // Only fields declared as URLs are validated; other strings are not expected to be URLs.
        // Non-strings are a type mismatch, which TypeCheck reports.
        if (!URL_TYPES.has(declared) || typeof context.value !== 'string') {
            return UrlValidator.safe(this.tool);
        }

        const reason = UrlValidator.validate(context.value);

        if (reason) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: { name: context.name, reason, value: context.value.slice(0, 200) },
            };
        }

        return UrlValidator.safe(this.tool);
    }

    // Returns the first rule the value breaks, or undefined when it is a valid URL.
    private static validate(value: string): string | undefined {
        if (value.length === 0) return 'empty';
        if (value.length > MAX_LENGTH) return 'too_long';
        if (FORBIDDEN_CHARS.test(value)) return 'forbidden_characters';
        if (!EXPLICIT_SCHEME.test(value)) return 'missing_scheme';

        let url: URL;
        try {
            url = new URL(value);
        } catch {
            return 'unparseable';
        }

        if (!ALLOWED_PROTOCOLS.has(url.protocol)) return 'disallowed_scheme';
        if (url.hostname === '') return 'missing_host';
        if (url.username || url.password) return 'embedded_credentials';

        return undefined;
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