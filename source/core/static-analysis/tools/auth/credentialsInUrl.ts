import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, pathOf, safe, violation } from '@tessera/core/static-analysis/shared';

// Values that are credentials whatever the parameter is called.
const SECRET_VALUES: { name: string; pattern: RegExp }[] = [
    { name: 'jwt', pattern: /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/ },
    { name: 'aws_access_key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
    { name: 'github_token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/ },
    { name: 'stripe_secret_key', pattern: /\b[sr]k_live_[A-Za-z0-9]{16,}/ },
    { name: 'slack_token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
];

export default class CredentialsInUrl extends Tool<ToolContextType.Full> {
    // query parameter names that carry credentials
    private readonly secretParameters: ReadonlySet<string>;

    constructor(config: ToolConfig<'credentials_in_url'>) {
        super({
            id: 'credentials_in_url',
            displayName: 'Credentials in URL',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.secretParameters = new Set(config.secretParameters);
    }

    override run(context: NormalizedRequest): ToolResult {
        const findings: { parameter: string; rule: string }[] = [];

        for (const field of context.fields) {
            if (field.location !== 'query' || field.value === null || field.value === undefined || String(field.value) === '') continue;
            const value = String(field.value);
            if (this.secretParameters.has(fieldLeaf(field.name))) {
                findings.push({ parameter: clip(field.name, 50), rule: 'secret_parameter' });
                continue;
            }
            const match = SECRET_VALUES.find(rule => rule.pattern.test(value));
            if (match) {
                findings.push({ parameter: clip(field.name, 50), rule: match.name });
            }
        }

        // "GET http://user:pass@host/ HTTP/1.1": userinfo in an absolute request target
        if (/^[a-z][a-z0-9+.-]*:\/\/[^/?#@]*:[^/?#@]*@/i.test(pathOf(context))) {
            findings.push({ parameter: 'request-target', rule: 'userinfo_in_url' });
        }

        // a violation: URLs end up in logs, browser history, proxies and Referer headers, so the secret
        // is leaked whatever the request was for. Names only in evidence, never the values.
        return findings.length > 0 ? violation(this.tool, { findings: findings.slice(0, 10) }) : safe(this.tool);
    }
}
