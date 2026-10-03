import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface Analysis {
    rules: string[];
    host?: string;
}

// hard-coded until we have enough infrastructure to support tool configuration
// Hosts a redirect may point to. Subdomains are allowed too ("app.example.com" matches "example.com").
const ALLOWED_HOSTS = ['example.com'];

// Fields that normally hold a redirect target, compared after lowercasing and removing "_" and "-".
// A generic "url" is left out on purpose: most URL fields are not redirects, and UrlValidator/Ssrf cover them.
const REDIRECT_FIELDS = new Set([
    'redirect', 'redirecturi', 'redirecturl', 'redirectto', 'return', 'returnto', 'returnurl', 'returnuri',
    'returnpath', 'next', 'nexturl', 'continue', 'dest', 'destination', 'goto', 'forward', 'target', 'callback',
    'callbackurl', 'successurl', 'failureurl', 'cancelurl', 'back', 'backurl', 'rurl', 'postlogin', 'postlogout',
]);

// Schemes that execute code or read local content when a browser follows them.
const DANGEROUS_SCHEMES = new Set(['javascript', 'data', 'vbscript', 'file', 'blob']);

const SCHEME = /^([a-z][a-z0-9+.-]*):/i;
const MAX_DECODE_ROUNDS = 3;

export default class OpenRedirect extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'open_redirect',
            displayName: 'Open redirect',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || !OpenRedirect.isRedirectField(context.name)) {
            return OpenRedirect.safe(this.tool);
        }

        const { rules, host } = OpenRedirect.analyze(context.value);

        if (rules.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: {
                    name: String(context.name).slice(0, 100),
                    location: context.location,
                    host: host?.slice(0, 100),
                    rules,
                },
            };
        }

        return OpenRedirect.safe(this.tool);
    }

    // "returnUrl", "user[return_url]" and "redirect-to" all count; only the last path segment is compared.
    private static isRedirectField(name: unknown): boolean {
        if (typeof name !== 'string') {
            return false;
        }
        const last = name.split(/[[\].]+/).filter(Boolean).pop() ?? '';
        return REDIRECT_FIELDS.has(last.toLowerCase().replace(/[_-]/g, ''));
    }

    // Folds the value the way a browser would before following it: percent-decoding (redirect targets are
    // often encoded), dropping tabs and newlines, trimming leading control characters, and "\" becoming "/".
    private static normalizeTarget(raw: string): string {
        let text = raw;
        for (let round = 0; round < MAX_DECODE_ROUNDS; round++) {
            let decoded: string;
            try {
                decoded = decodeURIComponent(text);
            } catch {
                break; // malformed escape, so keep what we have
            }
            if (decoded === text) {
                break;
            }
            text = decoded;
        }

        return text
            .replace(/[\t\r\n]/g, '')
            .replace(/^[\u0000-\u0020]+/, '')
            .replace(/\\/g, '/');
    }

    private static analyze(raw: string): Analysis {
        const value = OpenRedirect.normalizeTarget(raw);
        if (value === '') {
            return { rules: [] };
        }

        const scheme = value.match(SCHEME)?.[1].toLowerCase();

        if (scheme && DANGEROUS_SCHEMES.has(scheme)) {
            return { rules: ['dangerous_scheme'] };
        }

        let target: string;
        let protocolRelative = false;

        if (value.startsWith('//')) {
            target = `https:${value}`;
            protocolRelative = true;
        } else if (scheme === 'http' || scheme === 'https') {
            target = value;
        } else if (scheme) {
            return { rules: ['unexpected_scheme'] };
        } else {
            return { rules: [] }; // a relative path stays on the same site
        }

        let url: URL;
        try {
            url = new URL(target);
        } catch {
            return { rules: ['unparseable_target'] };
        }

        const rules: string[] = [];
        const host = url.hostname.toLowerCase().replace(/\.$/, '');

        if (!OpenRedirect.isAllowedHost(host)) {
            rules.push(protocolRelative ? 'protocol_relative_url' : 'external_host');

            // https:/evil.com and https:evil.com: not a proper "scheme://", yet browsers and parsers follow it
            if (!protocolRelative && !/^https?:\/\//i.test(value)) {
                rules.push('malformed_absolute_url');
            }
        }

        // https://trusted.example.com@evil.com and https://evil.com@trusted.example.com both rely on this
        if (url.username || url.password) {
            rules.push('embedded_credentials');
        }

        return { rules, host };
    }

    private static isAllowedHost(host: string): boolean {
        return ALLOWED_HOSTS.some(allowed => host === allowed || host.endsWith(`.${allowed}`));
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