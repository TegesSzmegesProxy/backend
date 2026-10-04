import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    ExpiringMap, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, failure, hashOf, header, normalizeIp, parseIpv4, safe, sessionKey, suspicious,
} from '@tessera/core/static-analysis/shared';

interface Binding {
    network: string;
    userAgent: string;
    platform: string;
}

export default class SessionBinding extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) session -> where it was last used.
    private readonly bindings: ExpiringMap<Binding>;

    constructor(config: ToolConfig<'session_binding'>, state: ToolState) {
        super({
            id: 'session_binding',
            displayName: 'Session binding',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.bindings = state.expiring<Binding>('bindings', config.sessionTtlMs);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const session = sessionKey(context);
        if (!session) {
            return safe(this.tool); // anonymous request, nothing is bound
        }
        if (!context.clientIp) {
            return failure(this.tool, { reason: 'missing_client_identity' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const key = session;
        const current: Binding = {
            network: SessionBinding.network(context.clientIp),
            userAgent: hashOf(header(context, 'user-agent') ?? ''),
            platform: header(context, 'sec-ch-ua-platform') ?? '',
        };

        const previous = await this.bindings.get(context.tenantId, key);
        // remember the latest binding, so one legitimate change (new Wi-Fi) is reported once, not forever
        await this.bindings.set(context.tenantId, key, current);

        if (!previous) {
            return safe(this.tool);
        }

        const changes: string[] = [];
        if (previous.network !== current.network) changes.push('network_changed');
        if (previous.userAgent !== current.userAgent) changes.push('user_agent_changed');
        if (previous.platform !== '' && current.platform !== '' && previous.platform !== current.platform) changes.push('platform_changed');

        return changes.length > 0 ? suspicious(this.tool, { changes, network: current.network }) : safe(this.tool);
    }

    // IPv4 /24 or IPv6 /48: wide enough that DHCP renewals and IPv6 privacy addresses don't count as a move.
    private static network(clientIp: string): string {
        const ip = normalizeIp(clientIp);
        const octets = parseIpv4(ip);
        if (octets) {
            return `${octets.slice(0, 3).join('.')}.0/24`;
        }
        return `${ip.split(':').slice(0, 3).join(':')}::/48`;
    }
}
