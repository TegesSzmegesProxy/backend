import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, browserFamily, failure, header, inCidr,
    metadataOf, safe, suspicious,
} from '@tessera/core/static-analysis/shared';

export default class TlsFingerprint extends Tool<ToolContextType.Full> {
    // JA3 hash -> library that produces it
    private readonly libraries: ReadonlyMap<string, string>;

    constructor(private readonly config: ToolConfig<'tls_fingerprint'>) {
        super({
            id: 'tls_fingerprint',
            displayName: 'TLS fingerprint',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
        this.libraries = new Map(config.libraryJa3.map(entry => [entry.ja3, entry.library]));
    }

    override run(context: NormalizedRequest): ToolResult {
        const ja3 = this.fingerprint(context);
        if (ja3 === undefined) {
            return failure(this.tool, { reason: 'missing_tls_fingerprint' });
        }

        const claimed = browserFamily(header(context, 'user-agent'));
        const library = this.libraries.get(ja3);

        if (claimed && library) {
            // says Chrome, handshakes like python-requests
            return suspicious(this.tool, { reason: 'browser_user_agent_with_library_fingerprint', claimed: claimed.family, library, ja3 });
        }
        if (claimed) {
            const actual = Object.entries(this.config.browserJa3).find(([, hashes]) => hashes.includes(ja3))?.[0];
            if (actual && actual !== claimed.family) {
                return suspicious(this.tool, { reason: 'fingerprint_of_another_browser', claimed: claimed.family, actual, ja3 });
            }
        }
        // unknown fingerprints are normal (new browser builds, other clients), so they pass
        return safe(this.tool);
    }

    // From the TLS layer when it writes metadata; from a header only when our own proxy set it, since a
    // client can put any header it likes.
    private fingerprint(context: NormalizedRequest): string | undefined {
        const fromMetadata = metadataOf(context).tls?.ja3;
        if (typeof fromMetadata === 'string' && fromMetadata !== '') {
            return fromMetadata.toLowerCase();
        }
        if (!this.config.trustedProxies.some(cidr => inCidr(context.clientIp, cidr))) {
            return undefined;
        }
        // where a TLS-terminating proxy in front of us passes the fingerprint on
        const fromHeader = this.config.fingerprintHeaders.map(name => header(context, name)).find(value => value !== undefined && /^[0-9a-f]{32}$/i.test(value));
        return fromHeader?.toLowerCase();
    }
}
