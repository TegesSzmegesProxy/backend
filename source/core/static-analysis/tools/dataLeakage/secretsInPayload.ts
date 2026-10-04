import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

interface SecretRule {
    name: string;
    pattern: RegExp;
    /** Formats specific enough that a match is a real credential, not a coincidence. */
    certain: boolean;
}

const MAX_LENGTH = 65_536;

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: SecretRule[] = [
    { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/, certain: true },
    { name: 'aws_access_key_id', pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/, certain: true },
    { name: 'aws_secret_access_key', pattern: /aws.{0,20}(?:secret|private).{0,20}['"=:\s][A-Za-z0-9/+]{40}\b/i, certain: false },
    { name: 'github_token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/, certain: true },
    { name: 'gitlab_token', pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/, certain: true },
    { name: 'slack_token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, certain: true },
    { name: 'slack_webhook', pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, certain: true },
    { name: 'stripe_secret_key', pattern: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/, certain: true },
    { name: 'google_api_key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, certain: true },
    { name: 'openai_or_anthropic_key', pattern: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b/, certain: true },
    { name: 'sendgrid_key', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, certain: true },
    { name: 'twilio_key', pattern: /\bSK[0-9a-f]{32}\b/, certain: false },
    { name: 'npm_token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/, certain: true },
    { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, certain: false },
    { name: 'connection_string_with_password', pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql):\/\/[^:\s/]+:[^@\s/]+@/i, certain: true },
];

export default class SecretsInPayload extends Tool<ToolContextType.Field> {
    // fields that are supposed to carry a credential (login forms, API key settings pages)
    private readonly credentialFields: ReadonlySet<string>;

    constructor(config: ToolConfig<'secrets_in_payload'>) {
        super({
            id: 'secrets_in_payload',
            displayName: 'Secrets in payload',
            category: ToolCategory.DataLeakage,
            contextType: ToolContextType.Field,
        });
        this.credentialFields = new Set(config.credentialFields);
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || this.credentialFields.has(fieldLeaf(context.name))) {
            return safe(this.tool);
        }

        const value = context.value.slice(0, MAX_LENGTH);
        const matched = RULES.filter(rule => rule.pattern.test(value));
        if (matched.length === 0) {
            return safe(this.tool);
        }

        // names only: echoing the secret into evidence would leak it a second time
        const evidence = { name: clip(context.name), location: context.location, secrets: matched.map(rule => rule.name) };
        // a live credential pasted into a comment, ticket or profile field must not be stored
        return matched.some(rule => rule.certain) ? violation(this.tool, evidence) : suspicious(this.tool, evidence);
    }
}
