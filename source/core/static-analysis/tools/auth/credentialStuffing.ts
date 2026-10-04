import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, accountOf, distinct, failure, hashOf, header,
    inRouteFilter, isStateChanging, lookupCidr, methodOf, pathOf, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

// config.limits: distinct accounts tried from one source before it is suspicious / blocked. ASNs and fingerprints
// are shared by many real users (carrier NAT, identical browsers), so by default they only make a request suspicious.
type Source = keyof ToolConfig<'credential_stuffing'>['limits'];

export default class CredentialStuffing extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) source|id -> hashed accounts tried.
    private readonly windows: Record<Source, SlidingWindow<string>>;

    constructor(private readonly config: ToolConfig<'credential_stuffing'>, state: ToolState) {
        super({
            id: 'credential_stuffing',
            displayName: 'Credential stuffing',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        // enough events per key to count past the highest limit
        const capacity = (source: Source, minimum: number): number => {
            const { suspicious, block } = config.limits[source];
            return Math.max(minimum, (block ?? suspicious) * 2 + 1);
        };
        this.windows = {
            ip: state.window('ip', config.windowMs, capacity('ip', 500)),
            fingerprint: state.window('fingerprint', config.windowMs, capacity('fingerprint', 500)),
            asn: state.window('asn', config.windowMs, capacity('asn', 2000)),
        };
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!inRouteFilter(pathOf(context), this.config.routes) || !isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }

        const account = accountOf(context);
        if (!account || !context.clientIp) {
            return failure(this.tool, { reason: !account ? 'missing_account' : 'missing_client_identity' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const accountHash = hashOf(account);
        const sources: Record<Source, string | undefined> = {
            ip: context.clientIp,
            fingerprint: hashOf(`${header(context, 'user-agent') ?? ''}|${header(context, 'accept-language') ?? ''}|${header(context, 'accept-encoding') ?? ''}`),
            asn: lookupCidr(context.clientIp, this.config.asnTable)?.asn.toString(),
        };

        let verdict: 'SAFE' | 'SUSPICIOUS' | 'POLICY_VIOLATION' = 'SAFE';
        const findings: { source: Source; distinctAccounts: number; threshold: number }[] = [];

        for (const source of Object.keys(sources) as Source[]) {
            const id = sources[source];
            if (id === undefined) continue;
            const events = await this.windows[source].record(context.tenantId, id, accountHash, now);
            const accounts = distinct(events, value => value).size;
            const { suspicious: soft, block } = this.config.limits[source];
            if (block !== undefined && accounts > block) {
                verdict = 'POLICY_VIOLATION';
                findings.push({ source, distinctAccounts: accounts, threshold: block });
            } else if (accounts > soft) {
                if (verdict === 'SAFE') verdict = 'SUSPICIOUS';
                findings.push({ source, distinctAccounts: accounts, threshold: soft });
            }
        }

        const evidence = { findings, windowMs: this.config.windowMs, asn: sources.asn };
        if (verdict === 'POLICY_VIOLATION') return violation(this.tool, evidence);
        if (verdict === 'SUSPICIOUS') return suspicious(this.tool, evidence);
        return safe(this.tool);
    }
}
