import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// Require an explicit "scheme://" up front. The WHATWG parser is lenient and also accepts
// "http:example.com" and "http:\\example.com", which most consumers would not treat as valid.
const EXPLICIT_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

// Whitespace and control characters, which the parser silently strips or rewrites.
const FORBIDDEN_CHARS = /[\u0000-\u0020\u007f-\u009f]/;

export default class UrlValidator extends Tool<ToolContextType.Field> {
    // URL.protocol values ("https:") of the allowed schemes
    private readonly allowedProtocols: ReadonlySet<string>;
    // declared field types this tool applies to; empty means every string field the step targets
    private readonly urlTypes: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'url_validator'>) {
        super({
            id: 'url_validator',
            displayName: 'URL validator',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
        this.allowedProtocols = new Set(config.allowedSchemes.map(scheme => `${scheme}:`));
        this.urlTypes = new Set(config.urlTypes.map(type => type.toLowerCase()));
    }

    override run(context: RequestField): ToolResult {
        const declared = typeof context.type === 'string' ? context.type.trim().toLowerCase() : '';

        // Only fields declared as URLs are validated; other strings are not expected to be URLs.
        // Non-strings are a type mismatch, which TypeCheck reports.
        if ((this.urlTypes.size > 0 && !this.urlTypes.has(declared)) || typeof context.value !== 'string') {
            return UrlValidator.safe(this.tool);
        }

        const reason = this.validate(context.value);

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
    private validate(value: string): string | undefined {
        if (value.length === 0) return 'empty';
        if (value.length > this.config.maxLength) return 'too_long';
        if (FORBIDDEN_CHARS.test(value)) return 'forbidden_characters';
        if (!EXPLICIT_SCHEME.test(value)) return 'missing_scheme';

        let url: URL;
        try {
            url = new URL(value);
        } catch {
            return 'unparseable';
        }

        if (!this.allowedProtocols.has(url.protocol)) return 'disallowed_scheme';
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