import { createHash } from 'node:crypto';
import { NormalizedRequest, RequestField } from '@tessera/shared/contracts';

// Generic, stateless helpers for reading a NormalizedRequest. No security logic lives here.

export interface ResponseSnapshot {
    status?: number;
    headers?: Record<string, string>;
    body?: string;
    size?: number;
}

/**
 * Keys tools read from NormalizedRequest.metadata. Only rawHeaders and httpVersion are written by the
 * normalizer today; the rest are filled by whatever layer can see them (TLS terminator, body parser,
 * response pass). Adjust the names to whatever your normalizer writes.
 */
export interface RequestMetadata {
    /** Node's IncomingMessage.rawHeaders: [name, value, name, value, ...] in arrival order, duplicates kept. */
    rawHeaders?: string[];
    httpVersion?: string;
    /** The body exactly as received, before parsing (needed to see duplicate JSON keys). */
    rawBody?: string;
    tls?: { ja3?: string; ja4?: string };
    /** How long receiving the request took. */
    timing?: { headersMs?: number; bodyMs?: number; bodyBytes?: number };
    /** Size of a Content-Encoding compressed body before and after decompression. */
    compression?: { compressedBytes?: number; decompressedBytes?: number };
    multipart?: { parts?: number; boundary?: string };
    chunked?: { chunkSizes?: string[]; extensions?: string[]; trailers?: string[] };
    /** Present when the request is a single WebSocket message rather than an HTTP request. */
    websocket?: { connectionId?: string; messageBytes?: number; frames?: number };
    /** Present only when tools run again after the upstream answered. */
    response?: ResponseSnapshot;
}

export function metadataOf(request: NormalizedRequest): RequestMetadata {
    const metadata = request.metadata;
    return typeof metadata === 'object' && metadata !== null ? (metadata as RequestMetadata) : {};
}

export function clip(value: unknown, max = 100): string {
    return String(value).slice(0, max);
}

export function hashOf(value: string): string {
    return createHash('sha256').update(value).digest('hex').slice(0, 32);
}

/** Case-insensitive header lookup. */
export function header(request: NormalizedRequest, name: string): string | undefined {
    const headers = request.headers ?? {};
    const direct = headers[name.toLowerCase()];
    if (direct !== undefined) {
        return String(direct);
    }
    const wanted = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === wanted) {
            return String(value);
        }
    }
    return undefined;
}

/** Raw header pairs in arrival order, or undefined when the normalizer did not capture them. */
export function rawHeaderPairs(request: NormalizedRequest): [string, string][] | undefined {
    const raw = metadataOf(request).rawHeaders;
    if (!Array.isArray(raw)) {
        return undefined;
    }
    const pairs: [string, string][] = [];
    for (let index = 0; index + 1 < raw.length; index += 2) {
        pairs.push([String(raw[index]), String(raw[index + 1])]);
    }
    return pairs;
}

/** Every value of a header, from raw headers when available, otherwise the folded value. */
export function headerValues(request: NormalizedRequest, name: string): string[] {
    const pairs = rawHeaderPairs(request);
    if (pairs) {
        return pairs.filter(([key]) => key.toLowerCase() === name.toLowerCase()).map(([, value]) => value);
    }
    const value = header(request, name);
    return value === undefined ? [] : [value];
}

/** The endpoint is "METHOD /path" (see the normalizer). */
export function methodOf(request: NormalizedRequest): string {
    const endpoint = String(request.endpoint ?? '');
    const space = endpoint.indexOf(' ');
    return (space === -1 ? endpoint : endpoint.slice(0, space)).toUpperCase();
}

export function pathOf(request: NormalizedRequest): string {
    const endpoint = String(request.endpoint ?? '');
    const space = endpoint.indexOf(' ');
    return space === -1 ? '/' : endpoint.slice(space + 1) || '/';
}

export function isStateChanging(method: string): boolean {
    return !['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method.toUpperCase());
}

/** Lowercased path without query and trailing slash, for comparing against configured routes. */
export function routeKey(path: string): string {
    const bare = path.split('?')[0].toLowerCase();
    return bare.length > 1 ? bare.replace(/\/+$/, '') || '/' : bare || '/';
}

/** True when the path is one of the routes or below one ("/admin" matches "/admin/users"). */
export function matchesRoute(path: string, routes: readonly string[]): boolean {
    const key = routeKey(path);
    return routes.some(route => key === route || key.startsWith(`${route}/`));
}

/** A tool's optional route filter: no filter means every endpoint the tool's step is attached to. */
export function inRouteFilter(path: string, routes: readonly string[] | undefined): boolean {
    return routes === undefined || matchesRoute(path, routes);
}

/** "user[return_url]", "profile.returnUrl", "return-url" -> "returnurl" */
export function fieldLeaf(name: unknown): string {
    if (typeof name !== 'string') {
        return '';
    }
    const segments = name.split(/[[\].]+/).filter(Boolean);
    // array indexes ("items.0") are not names, so skip back to the last real segment
    while (segments.length > 1 && /^\d+$/.test(segments[segments.length - 1])) {
        segments.pop();
    }
    return (segments.pop() ?? '').toLowerCase().replace(/[_-]/g, '');
}

export function findField(request: NormalizedRequest, leaves: ReadonlySet<string>): RequestField | undefined {
    return request.fields.find(field => leaves.has(fieldLeaf(field.name)));
}

export function stringFields(request: NormalizedRequest): (RequestField & { value: string })[] {
    return request.fields.filter((field): field is RequestField & { value: string } => typeof field.value === 'string');
}

/** All cookies in order, duplicates kept. */
export function cookiesOf(request: NormalizedRequest): [string, string][] {
    return headerValues(request, 'cookie')
        .flatMap(value => value.split(';'))
        .map(part => part.trim())
        .filter(Boolean)
        .map(part => {
            const equals = part.indexOf('=');
            return equals === -1 ? [part, ''] as [string, string] : [part.slice(0, equals).trim(), part.slice(equals + 1).trim()] as [string, string];
        });
}

// ---------- IP addresses ----------

/** "1.2.3.4:80" -> "1.2.3.4", "[::1]:80" -> "::1", "::ffff:1.2.3.4" -> "1.2.3.4" */
export function normalizeIp(value: unknown): string {
    let ip = typeof value === 'string' ? value.trim() : '';
    const bracketed = ip.match(/^\[([^\]]+)\](?::\d{1,5})?$/);
    if (bracketed) {
        ip = bracketed[1];
    } else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(ip)) {
        ip = ip.slice(0, ip.lastIndexOf(':'));
    }
    ip = ip.split('%')[0].toLowerCase();
    const mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    return mapped ? mapped[1] : ip;
}

export function parseIpv4(address: string): number[] | undefined {
    const match = address.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!match) {
        return undefined;
    }
    const octets = match.slice(1).map(Number);
    return octets.every(octet => octet <= 255) ? octets : undefined;
}

function ipv4ToInt(octets: number[]): number {
    return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
}

/** IPv4 only; IPv6 addresses never match. */
export function inCidr(ip: string, cidr: string): boolean {
    const [base, bitsText] = cidr.split('/');
    const address = parseIpv4(normalizeIp(ip));
    const network = parseIpv4(base);
    const bits = bitsText === undefined ? 32 : Number(bitsText);
    if (!address || !network || !Number.isInteger(bits) || bits < 0 || bits > 32) {
        return false;
    }
    if (bits === 0) {
        return true;
    }
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return ((ipv4ToInt(address) & mask) >>> 0) === ((ipv4ToInt(network) & mask) >>> 0);
}

export function lookupCidr<T extends { cidr: string }>(ip: string, table: readonly T[]): T | undefined {
    return table.find(entry => inCidr(ip, entry.cidr));
}

export function isPrivateIpv4(ip: string): boolean {
    return ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8']
        .some(cidr => inCidr(ip, cidr));
}

// ---------- tokens and identity ----------

export interface DecodedJwt {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
}

/** Decodes without verifying. Only for inspecting attacker-controlled structure, never for trust. */
export function decodeJwt(token: string): DecodedJwt | undefined {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
        return undefined;
    }
    try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        if (typeof header !== 'object' || header === null || typeof payload !== 'object' || payload === null) {
            return undefined;
        }
        return { header, payload, signature: parts[2] };
    } catch {
        return undefined;
    }
}

export function bearerToken(request: NormalizedRequest): string | undefined {
    const authorization = header(request, 'authorization');
    const match = authorization?.match(/^\s*bearer\s+(\S+)\s*$/i);
    return match ? match[1] : undefined;
}

const SESSION_COOKIES = new Set(['session', 'sid', 'connect.sid', 'sessionid', 'phpsessid', 'jsessionid', 'asp.net_sessionid', 'auth', 'token', 'access_token']);

/** A stable, hashed identifier of the caller's credentials (bearer token or session cookie). */
export function sessionKey(request: NormalizedRequest): string | undefined {
    const bearer = bearerToken(request);
    if (bearer) {
        return hashOf(`bearer|${bearer}`);
    }
    const cookie = cookiesOf(request).find(([name, value]) => SESSION_COOKIES.has(name.toLowerCase()) && value !== '');
    return cookie ? hashOf(`cookie|${cookie[0]}|${cookie[1]}`) : undefined;
}

export function hasCredentials(request: NormalizedRequest): boolean {
    return header(request, 'authorization') !== undefined || sessionKey(request) !== undefined;
}

const ACCOUNT_FIELDS = new Set(['username', 'user', 'login', 'email', 'emailaddress', 'account', 'phone', 'phonenumber', 'userid']);

/** The account a login/reset/OTP request is about: an identity field, else the bearer token's subject. */
export function accountOf(request: NormalizedRequest): string | undefined {
    const field = request.fields.find(f => ACCOUNT_FIELDS.has(fieldLeaf(f.name)) && (typeof f.value === 'string' || typeof f.value === 'number'));
    if (field) {
        const value = String(field.value).trim().toLowerCase();
        if (value !== '') return value;
    }
    const bearer = bearerToken(request);
    const subject = bearer ? decodeJwt(bearer)?.payload['sub'] : undefined;
    return typeof subject === 'string' || typeof subject === 'number' ? String(subject) : undefined;
}

// ---------- text ----------

/** Percent-decodes until stable, at most `rounds` times. Returns every distinct layer, starting with the input. */
export function decodeLayers(value: string, rounds = 3): string[] {
    const layers = [value];
    let current = value;
    for (let round = 0; round < rounds; round++) {
        let next: string;
        try {
            next = decodeURIComponent(current.replace(/\+/g, ' '));
        } catch {
            break; // malformed escape, keep what we have
        }
        if (next === current) break;
        layers.push(next);
        current = next;
    }
    return layers;
}

/** Visits every string and key in a parsed value, bounded in depth and node count. */
export function walkValue(
    value: unknown,
    visit: (kind: 'key' | 'value', text: string, path: string) => void,
    limits: { maxDepth?: number; maxNodes?: number } = {},
): void {
    const maxDepth = limits.maxDepth ?? 32;
    const maxNodes = limits.maxNodes ?? 10_000;
    let nodes = 0;

    const walk = (node: unknown, depth: number, path: string): void => {
        if (depth > maxDepth || nodes++ >= maxNodes) return;
        if (typeof node === 'string') {
            visit('value', node, path);
        } else if (Array.isArray(node)) {
            node.forEach((item, index) => walk(item, depth + 1, `${path}[${index}]`));
        } else if (typeof node === 'object' && node !== null) {
            for (const [key, child] of Object.entries(node)) {
                visit('key', key, path);
                walk(child, depth + 1, path ? `${path}.${key}` : key);
            }
        }
    };

    walk(value, 0, '');
}

/** "/api/users/42/orders/9f1c..." -> "/api/users/{id}/orders/{id}", so per-route state groups resources. */
export function routeTemplate(path: string): string {
    return routeKey(path)
        .split('/')
        .map(segment => (/^\d+$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[0-9a-f]{16,}$/i.test(segment) ? '{id}' : segment))
        .join('/');
}

export interface UrlAuthority {
    /** "http:", or "" for protocol-relative "//host" */
    scheme: string;
    authority: string;
    /** Host exactly as written (lowercased, no userinfo, port or brackets), before any URL parser rewrites it. */
    host: string;
}

// matchAll clones the regex, so the g flag is safe on this shared constant.
const AUTHORITY_PATTERN = /(?:\b([a-z][a-z0-9+.-]*:))?\/\/([^/?#\s"'<>\\]+)/gi;

/** Authorities of every explicit or protocol-relative URL in a value, at most `max`. */
export function urlAuthorities(value: string, max = 20): UrlAuthority[] {
    const results: UrlAuthority[] = [];
    for (const match of value.matchAll(AUTHORITY_PATTERN)) {
        const authority = match[2];
        const hostPort = authority.slice(authority.lastIndexOf('@') + 1);
        const bracketed = hostPort.match(/^\[([^\]]*)\]/);
        const host = (bracketed ? bracketed[1] : hostPort.replace(/:\d*$/, '')).toLowerCase();
        results.push({ scheme: (match[1] ?? '').toLowerCase(), authority, host });
        if (results.length >= max) break;
    }
    return results;
}

export interface ClaimedBrowser {
    family: 'chrome' | 'firefox' | 'safari';
    major: number;
}

/** The browser a User-Agent claims to be (Edge, Opera and Brave count as Chrome), or undefined. */
export function browserFamily(userAgent: string | undefined): ClaimedBrowser | undefined {
    if (!userAgent || !/^Mozilla\/5\.0 /.test(userAgent)) return undefined;
    const firefox = userAgent.match(/\bFirefox\/(\d+)/);
    if (firefox) return { family: 'firefox', major: Number(firefox[1]) };
    const chrome = userAgent.match(/\b(?:Chrome|CriOS|Chromium)\/(\d+)/);
    if (chrome) return { family: 'chrome', major: Number(chrome[1]) };
    const safari = userAgent.match(/\bVersion\/(\d+)[\d.]* (?:Mobile\/\S+ )?Safari\//);
    if (safari) return { family: 'safari', major: Number(safari[1]) };
    return undefined;
}
