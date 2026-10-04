import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, browserFamily, failure, header, metadataOf, rawHeaderPairs, safe, suspicious } from '@tessera/core/static-analysis/shared';

// Default header order of common HTTP libraries (HTTP/1.1, lowercased), mock subset.
const LIBRARY_ORDERS: { library: string; order: string[] }[] = [
    { library: 'python-requests', order: ['host', 'user-agent', 'accept-encoding', 'accept', 'connection'] },
    { library: 'curl', order: ['host', 'user-agent', 'accept'] },
    { library: 'go-http-client', order: ['host', 'user-agent', 'accept-encoding'] },
    { library: 'node-fetch', order: ['accept', 'user-agent', 'accept-encoding', 'host', 'connection'] },
    { library: 'axios', order: ['accept', 'user-agent', 'host', 'connection'] },
];

// Headers every real browser sends on a navigation or fetch.
const BROWSER_HEADERS = ['accept', 'accept-language', 'accept-encoding'];

export default class HeaderOrderFingerprint extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'header_order_fingerprint',
            displayName: 'Header order fingerprint',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const claimed = browserFamily(header(context, 'user-agent'));
        if (!claimed) {
            return safe(this.tool); // only a client pretending to be a browser is judged here
        }

        const pairs = rawHeaderPairs(context);
        if (!pairs) {
            return failure(this.tool, { reason: 'raw_headers_unavailable' });
        }

        const names = pairs.map(([name]) => name.toLowerCase());
        const findings: { rule: string; detail?: string }[] = [];

        const library = LIBRARY_ORDERS.find(({ order }) => names.length === order.length && order.every((name, index) => names[index] === name));
        if (library) {
            findings.push({ rule: 'library_header_order', detail: library.library });
        }

        const missing = BROWSER_HEADERS.filter(name => !names.includes(name));
        if (missing.length > 0) {
            findings.push({ rule: 'missing_browser_headers', detail: missing.join(',') });
        }

        // browsers put Host first on HTTP/1.1; HTTP/2 has no Host header (it's :authority)
        if (metadataOf(context).httpVersion?.startsWith('1') && names.includes('host') && names[0] !== 'host') {
            findings.push({ rule: 'host_not_first' });
        }

        // Chromium >= 80 sends Sec-Fetch-* on every request; Firefox >= 90 and Safari >= 16.4 too
        const sendsFetchMetadata = claimed.family === 'chrome' ? claimed.major >= 80 : claimed.family === 'firefox' ? claimed.major >= 90 : claimed.major >= 17;
        if (sendsFetchMetadata && !names.some(name => name.startsWith('sec-fetch-'))) {
            findings.push({ rule: 'missing_fetch_metadata' });
        }

        return findings.length > 0 ? suspicious(this.tool, { claimed: claimed.family, findings }) : safe(this.tool);
    }
}
