import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, distinct, failure, fieldLeaf, hashOf, inRouteFilter, pathOf, safe,
    suspicious, violation,
} from '@tessera/core/static-analysis/shared';

export default class SmsEmailPumping extends Tool<ToolContextType.Full> {
    // Windows in Redis, per tenant.
    private readonly byClient: SlidingWindow<string>;
    private readonly byTenant: SlidingWindow<string>;
    private readonly byDestination: SlidingWindow<true>;
    private readonly destinationFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'sms_email_pumping'>, state: ToolState) {
        super({
            id: 'sms_email_pumping',
            displayName: 'SMS / email pumping',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.byClient = state.window<string>('byClient', config.windowMs, config.clientDestinations.block * 4 + 4);
        this.byTenant = state.window<string>('byTenant', config.windowMs, config.tenantSuspiciousDestinations * 2);
        this.byDestination = state.window<true>('byDestination', config.windowMs, config.destinationMaxSends + 1);
        this.destinationFields = new Set(config.destinationFields);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!inRouteFilter(pathOf(context), this.config.routes)) {
            return safe(this.tool);
        }

        const field = context.fields.find(candidate => this.destinationFields.has(fieldLeaf(candidate.name)) && typeof candidate.value === 'string');
        if (!field) {
            return failure(this.tool, { reason: 'missing_destination' });
        }

        const destination = String(field.value).trim().toLowerCase().replace(/[\s().-]/g, '').replace(/^00/, '+');
        const destinationHash = hashOf(destination);
        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();

        const clientDestinations = distinct(await this.byClient.record(context.tenantId, context.clientIp, destinationHash, now), value => value).size;
        const tenantDestinations = distinct(await this.byTenant.record(context.tenantId, 'all', destinationHash, now), value => value).size;
        const sendsToDestination = (await this.byDestination.record(context.tenantId, destinationHash, true, now)).length;

        const { clientDestinations: clientLimits, destinationMaxSends, tenantSuspiciousDestinations, highRiskPrefixes, windowMs } = this.config;
        const violations: string[] = [];
        const suspicions: string[] = [];
        if (clientDestinations > clientLimits.block) violations.push('client_sending_to_many_destinations');
        else if (clientDestinations > clientLimits.suspicious) suspicions.push('client_sending_to_several_destinations');
        // one number or address bombed with codes
        if (sendsToDestination > destinationMaxSends) violations.push('destination_flooded');
        // all clients together: a distributed pumping campaign
        if (tenantDestinations > tenantSuspiciousDestinations) suspicions.push('tenant_wide_send_burst');

        // international prefixes with high termination fees, the ones toll-fraud rings own numbers in
        const prefix = highRiskPrefixes.find(candidate => destination.startsWith(candidate));
        if (prefix) suspicions.push('high_risk_number_prefix');

        const evidence = {
            findings: [...violations, ...suspicions],
            clientDestinations,
            tenantDestinations,
            sendsToDestination,
            prefix,
            windowMs,
        };
        if (violations.length > 0) return violation(this.tool, evidence);
        return suspicions.length > 0 ? suspicious(this.tool, evidence) : safe(this.tool);
    }
}
