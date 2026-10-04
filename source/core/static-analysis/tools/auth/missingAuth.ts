import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface Rejected {
    source: 'authorization' | 'header' | 'cookie';
    name: string;
    reason: 'empty' | 'placeholder';
}

// hard-coded until we have enough infrastructure to support tool configuration
// Endpoints that may be called without credentials. Everything else requires them (secure by default).
// "/docs/*" matches "/docs" and everything below it. Replace these examples with your real public routes.
const PUBLIC_ENDPOINTS = ['/', '/health', '/healthz', '/login', '/register', '/docs/*'];

// Headers that carry a credential on their own, compared lowercased.
const CREDENTIAL_HEADERS = new Set([
    'x-api-key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token', 'x-session-token', 'x-token',
]);

// Cookie names that carry a session or token, compared after lowercasing, removing a "__host-" or "__secure-"
// prefix, and removing "_", "-" and ".". Add your own session cookie name.
const CREDENTIAL_COOKIES = new Set([
    'session', 'sessionid', 'sessid', 'sid', 'jsessionid', 'phpsessid', 'connectsid', 'laravelsession',
    'token', 'accesstoken', 'authtoken', 'idtoken', 'jwt', 'auth', 'authorization',
]);

// Values clients send when a variable was never set: "Authorization: Bearer undefined".
const PLACEHOLDERS = new Set(['null', 'undefined', 'nan', 'none', 'false', 'true', 'bearer', 'token', '[object object]']);

const AUTHORIZATION_VALUE = /^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)(?: +(.+))?$/;
const MAX_DECODE_ROUNDS = 3;
const MAX_COOKIES = 100;

export default class MissingAuthentication extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'missing_authentication',
            displayName: 'Missing authentication',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        if (typeof context.endpoint !== 'string' || context.endpoint.trim() === '') {
            // without an endpoint we can't tell whether authentication was required
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { reason: 'missing_endpoint' },
            };
        }

        const path = MissingAuthentication.normalizePath(context.endpoint);

        // a path that can't be normalized is never treated as public
        if (path !== undefined && MissingAuthentication.isPublic(path)) {
            return MissingAuthentication.safe(this.tool);
        }

        const rejected: Rejected[] = [];
        if (MissingAuthentication.hasCredential(context.headers ?? {}, rejected)) {
            return MissingAuthentication.safe(this.tool);
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'POLICY_VIOLATION',
            // header and cookie names only: credential values are never included
            evidence: {
                endpoint: String(context.endpoint).slice(0, 200),
                reason: rejected.length > 0 ? 'unusable_credentials' : 'no_credentials',
                rejected: rejected.length > 0 ? rejected : undefined,
            },
        };
    }

    // True when the request carries at least one credential that is present and not an obvious placeholder.
    // Whether the credential is valid is not decided here.
    private static hasCredential(headers: Record<string, string>, rejected: Rejected[]): boolean {
        let found = false;

        for (const [rawName, value] of Object.entries(headers)) {
            const name = rawName.toLowerCase();
            if (typeof value !== 'string') {
                continue;
            }

            if (name === 'authorization' || name === 'proxy-authorization') {
                const match = value.trim().match(AUTHORIZATION_VALUE);
                const credentials = match?.[2]?.trim() ?? '';
                if (credentials === '') {
                    rejected.push({ source: 'authorization', name, reason: 'empty' });
                } else if (PLACEHOLDERS.has(credentials.toLowerCase())) {
                    rejected.push({ source: 'authorization', name, reason: 'placeholder' });
                } else {
                    found = true;
                }
            } else if (CREDENTIAL_HEADERS.has(name)) {
                const credential = value.trim();
                if (credential === '') {
                    rejected.push({ source: 'header', name, reason: 'empty' });
                } else if (PLACEHOLDERS.has(credential.toLowerCase())) {
                    rejected.push({ source: 'header', name, reason: 'placeholder' });
                } else {
                    found = true;
                }
            } else if (name === 'cookie') {
                for (const part of value.split(';').slice(0, MAX_COOKIES)) {
                    const separator = part.indexOf('=');
                    if (separator < 1) {
                        continue;
                    }

                    const cookieName = part.slice(0, separator).trim();
                    const normalized = cookieName.toLowerCase().replace(/^__(?:host|secure)-/, '').replace(/[_.-]/g, '');
                    if (!CREDENTIAL_COOKIES.has(normalized)) {
                        continue;
                    }

                    const cookieValue = part.slice(separator + 1).trim().replace(/^"(.*)"$/, '$1');
                    if (cookieValue === '') {
                        rejected.push({ source: 'cookie', name: cookieName.slice(0, 100), reason: 'empty' });
                    } else if (PLACEHOLDERS.has(cookieValue.toLowerCase())) {
                        rejected.push({ source: 'cookie', name: cookieName.slice(0, 100), reason: 'placeholder' });
                    } else {
                        found = true;
                    }
                }
            }
        }

        return found;
    }

    private static isPublic(path: string): boolean {
        return PUBLIC_ENDPOINTS.some(entry => {
            if (entry.endsWith('/*')) {
                const base = entry.slice(0, -2).toLowerCase();
                return path === base || path.startsWith(`${base}/`);
            }
            return path === entry.toLowerCase();
        });
    }

    // Folds the endpoint to the path a server would route, so "/public/../admin", "/%2e%2e/admin", "//health",
    // "/health;x=1" and "/HEALTH/" can't be used to look public (or to hide). Returns undefined if it can't be folded.
    private static normalizePath(endpoint: string): string | undefined {
        let path = endpoint.trim();

        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) {
            try {
                path = new URL(path).pathname;
            } catch {
                return undefined;
            }
        }

        path = path.split(/[?#]/)[0];

        for (let round = 0; round < MAX_DECODE_ROUNDS; round++) {
            let decoded: string;
            try {
                decoded = decodeURIComponent(path);
            } catch {
                return undefined; // malformed escape
            }
            if (decoded === path) {
                break;
            }
            path = decoded;
        }

        if (/[\u0000-\u001f\u007f]/.test(path)) {
            return undefined;
        }

        const segments: string[] = [];
        for (const raw of path.replace(/\\/g, '/').split('/')) {
            const segment = raw.split(';')[0].trim(); // drop path parameters such as ";jsessionid=..."
            if (segment === '' || segment === '.') {
                continue;
            }
            if (segment === '..') {
                segments.pop();
                continue;
            }
            segments.push(segment.toLowerCase());
        }

        return `/${segments.join('/')}`;
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