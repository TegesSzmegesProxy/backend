import { createHmac, randomBytes } from 'node:crypto';
import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, accountOf, distinct, failure, fieldLeaf, hashOf, inRouteFilter, isStateChanging,
    methodOf, pathOf, safe, suspicious,
} from '@tessera/core/static-analysis/shared';

export default class PasswordSpraying extends Tool<ToolContextType.Full> {
    // Passwords are only kept as an HMAC under a key that never leaves this process, so the state can't be
    // turned back into passwords. A restart rotates the key and forgets the window, which is acceptable.
    private readonly key = randomBytes(32);
    // (Redis, per tenant) password -> accounts it was tried against
    private readonly byPassword: SlidingWindow<string>;
    // (Redis, per tenant) client -> { account, password } pairs
    private readonly byClient: SlidingWindow<{ account: string; password: string }>;
    private readonly passwordFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'password_spraying'>, state: ToolState) {
        super({
            id: 'password_spraying',
            displayName: 'Password spraying',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.byPassword = state.window<string>('byPassword', config.windowMs, Math.max(500, config.accountsPerPassword * 2));
        this.byClient = state.window<{ account: string; password: string }>('byClient', config.windowMs, Math.max(500, config.accountsPerClient * 2));
        this.passwordFields = new Set(config.passwordFields);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!inRouteFilter(pathOf(context), this.config.routes) || !isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }

        const account = accountOf(context);
        const passwordField = context.fields.find(field => this.passwordFields.has(fieldLeaf(field.name)) && typeof field.value === 'string');
        if (!account || !passwordField) {
            return failure(this.tool, { reason: !account ? 'missing_account' : 'missing_password' });
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const accountHash = hashOf(account);
        const passwordHash = createHmac('sha256', this.key).update(String(passwordField.value)).digest('hex').slice(0, 32);

        const { windowMs, accountsPerPassword, accountsPerClient, passwordsPerClient } = this.config;
        const findings: Record<string, number | string>[] = [];

        const tried = await this.byPassword.record(context.tenantId, passwordHash, accountHash, now);
        const accountsForPassword = distinct(tried, value => value).size;
        if (accountsForPassword >= accountsPerPassword) {
            findings.push({ rule: 'password_reused_across_accounts', accounts: accountsForPassword, threshold: accountsPerPassword });
        }

        const client = await this.byClient.record(context.tenantId, context.clientIp, { account: accountHash, password: passwordHash }, now);
        const clientAccounts = distinct(client, value => value.account).size;
        const clientPasswords = distinct(client, value => value.password).size;
        if (clientAccounts >= accountsPerClient && clientPasswords <= passwordsPerClient) {
            findings.push({ rule: 'few_passwords_many_accounts', accounts: clientAccounts, passwords: clientPasswords });
        }

        return findings.length > 0 ? suspicious(this.tool, { findings, windowMs }) : safe(this.tool);
    }
}
