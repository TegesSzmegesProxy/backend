import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface Finding {
    rule: string;
    source: 'path' | 'query' | 'body' | 'cookie';
    name?: string;
}

// Names under which session IDs travel, compared after lowercasing and removing "_", "-", "." and spaces.
// ASP.NET also appends a random suffix ("ASPSESSIONIDQQQABCDE"), so that one is matched by prefix.
const SESSION_NAMES = new Set([
    'sessionid', 'sessid', 'sid', 'session', 'sessionkey', 'sessiontoken', 'phpsessid', 'jsessionid',
    'aspnetsessionid', 'connectsid', 'laravelsession', 'cfid', 'cftoken',
]);

// Locations that are not an attacker-reachable delivery channel for a session ID, or are handled separately.
// Adjust to the values RequestField.location actually takes.
const SKIPPED_FIELD_LOCATIONS = new Set(['query', 'header', 'headers', 'cookie', 'cookies']);

// ;jsessionid=ABC in the path: the classic URL-rewriting form of session fixation.
const PATH_SESSION_PARAM = /;\s*(?:jsessionid|phpsessid|sessionid|sid)\s*=/i;

// Ways to plant a cookie from a request value: header injection, meta tag, or script.
const COOKIE_INJECTION = /set-cookie\s*:|http-equiv\s*=\s*["']?\s*set-cookie|document\s*\.\s*cookie\s*=/i;

// Characters allowed in a session cookie value (base64, base64url, hex, UUID, and percent-encoding).
const VALID_SESSION_CHARS = /^[A-Za-z0-9._~+/=:%-]+$/;

// hard-coded until we have enough infrastructure to support tool configuration
const MIN_SESSION_ID_LENGTH = 16;
const MIN_DISTINCT_CHARS = 6;
const MAX_SESSION_ID_LENGTH = 512;
const MAX_ENTRIES = 500;
const MAX_DECODE_ROUNDS = 2;

export default class SessionFixation extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'session_fixation',
            displayName: 'Session fixation',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const findings: Finding[] = [];
        const seen = new Set<string>();

        const add = (rule: string, source: Finding['source'], name?: string): void => {
            const id = `${rule}|${source}|${name ?? ''}`;
            if (!seen.has(id)) {
                seen.add(id);
                findings.push({ rule, source, name: name?.slice(0, 100) });
            }
        };

        // 1. session ID carried in the path (";jsessionid=...")
        if (typeof context.endpoint === 'string' && PATH_SESSION_PARAM.test(context.endpoint)) {
            add('session_id_in_path', 'path');
        }

        // 2. session ID or cookie-planting payload carried in the query string
        for (const [name, value] of Object.entries(context.query ?? {}).slice(0, MAX_ENTRIES)) {
            if (SessionFixation.isSessionName(name)) {
                add('session_id_in_query', 'query', name);
            }
            if (SessionFixation.plantsCookie(value)) {
                add('cookie_injection', 'query', name);
            }
        }

        // 3. the same, in body-like fields (query and cookie locations are covered elsewhere)
        for (const field of (context.fields ?? []).slice(0, MAX_ENTRIES)) {
            if (SKIPPED_FIELD_LOCATIONS.has(String(field.location).toLowerCase())) {
                continue;
            }
            if (typeof field.name === 'string' && SessionFixation.isSessionName(field.name)) {
                add('session_id_in_body', 'body', field.name);
            }
            if (typeof field.value === 'string' && SessionFixation.plantsCookie(field.value)) {
                add('cookie_injection', 'body', field.name);
            }
        }

        // 4. the Cookie header: repeated session cookies and session IDs that don't look server-issued
        const cookieHeader = Object.entries(context.headers ?? {}).find(([name]) => name.toLowerCase() === 'cookie')?.[1];
        if (typeof cookieHeader === 'string') {
            SessionFixation.inspectCookies(cookieHeader, add);
        }

        if (findings.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                // rule, source and name only: session ID values are never included
                evidence: { endpoint: String(context.endpoint).slice(0, 200), findings },
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    private static inspectCookies(header: string, add: (rule: string, source: Finding['source'], name?: string) => void): void {
        const counts = new Map<string, number>();

        for (const part of header.split(';').slice(0, MAX_ENTRIES)) {
            const separator = part.indexOf('=');
            if (separator < 1) {
                continue;
            }

            const name = part.slice(0, separator).trim();
            if (!SessionFixation.isSessionName(name)) {
                continue;
            }

            counts.set(name, (counts.get(name) ?? 0) + 1);

            const value = part.slice(separator + 1).trim().replace(/^"(.*)"$/, '$1');
            if (value === '') {
                continue;
            }

            if (value.length > MAX_SESSION_ID_LENGTH || !VALID_SESSION_CHARS.test(value)) {
                add('malformed_session_id', 'cookie', name);
            } else if (value.length < MIN_SESSION_ID_LENGTH || new Set(value).size < MIN_DISTINCT_CHARS) {
                add('weak_session_id', 'cookie', name);
            }
        }

        // Two cookies with the same name: one planted from a sibling subdomain ("cookie tossing"),
        // and the browser sends both.
        for (const [name, count] of counts) {
            if (count > 1) {
                add('duplicate_session_cookie', 'cookie', name);
            }
        }
    }

    private static isSessionName(name: string): boolean {
        // "user[session_id]" and "auth.sid" are compared by their last segment
        const last = name.split(/[[\].]+/).filter(Boolean).pop() ?? '';
        const normalized = last.toLowerCase().replace(/[\s_.-]/g, '');
        return SESSION_NAMES.has(normalized) || normalized.startsWith('aspsessionid');
    }

    // Header-injection payloads are usually percent-encoded ("%0d%0aSet-Cookie:"), so decode before testing.
    private static plantsCookie(value: string): boolean {
        let text = value;
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
        return COOKIE_INJECTION.test(text);
    }
}