import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, headerValues, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

export default class HostHeaderInjection extends Tool<ToolContextType.Full> {
    private readonly allowedHosts: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'host_header_injection'>) {
        super({
            id: 'host_header_injection',
            displayName: 'Host header injection',
            category: ToolCategory.Protocol,
            contextType: ToolContextType.Full,
        });
        this.allowedHosts = new Set(config.allowedHosts);
    }

    override run(context: NormalizedRequest): ToolResult {
        const hosts = headerValues(context, 'host');
        if (hosts.length === 0) {
            return violation(this.tool, { reason: 'missing_host' });
        }

        const host = hosts[0];
        const problem = this.check(host);
        if (problem) {
            return violation(this.tool, { reason: problem, host: clip(host) });
        }

        const hostName = HostHeaderInjection.hostname(host);
        const mismatches: { header: string; value: string; allowed: boolean }[] = [];
        // headers that override or accompany Host in some frameworks (password-reset links, absolute redirects)
        for (const name of this.config.alternateHostHeaders) {
            const value = header(context, name);
            if (value === undefined) continue;
            // "a.example.com, evil.com": each hop appends; any of them can be picked
            for (const candidate of value.split(',').map(part => part.trim())) {
                if (HostHeaderInjection.hostname(candidate) !== hostName) {
                    mismatches.push({ header: name, value: clip(candidate), allowed: this.check(candidate) === undefined });
                }
            }
        }
        const forwarded = header(context, 'forwarded')?.match(/host\s*=\s*"?([^";,]+)/i)?.[1];
        if (forwarded !== undefined && HostHeaderInjection.hostname(forwarded) !== hostName) {
            mismatches.push({ header: 'forwarded', value: clip(forwarded), allowed: this.check(forwarded) === undefined });
        }

        if (mismatches.some(mismatch => !mismatch.allowed)) {
            return violation(this.tool, { reason: 'alternate_host_not_allowed', host: clip(host), mismatches });
        }
        if (mismatches.length > 0) {
            return suspicious(this.tool, { reason: 'host_mismatch', host: clip(host), mismatches });
        }
        return safe(this.tool);
    }

    // Returns why a Host value is unacceptable, or undefined.
    private check(value: string): string | undefined {
        if (/[\s@/\\?#]/.test(value) || /[\u0000-\u001f\u007f-￿]/.test(value)) return 'malformed_host';
        const match = value.match(/^(\[[0-9a-f:.]+\]|[^:]+)(?::(\d{1,5}))?$/i);
        if (!match) return 'malformed_host';
        if (match[2] !== undefined && Number(match[2]) > 65535) return 'invalid_port';
        const name = match[1].toLowerCase().replace(/\.$/, '');
        return this.allowedHosts.has(name) ? undefined : 'host_not_allowed';
    }

    private static hostname(value: string): string {
        return value.trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
    }
}
