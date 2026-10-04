import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, accountOf, distinct, failure, fieldLeaf, hashOf, inRouteFilter, isStateChanging,
    methodOf, pathOf, safe, sessionKey, violation,
} from '@tessera/core/static-analysis/shared';

export default class OtpBruteForce extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) subject -> guessed codes (hashed).
    private readonly bySubject: SlidingWindow<string>;
    private readonly byClient: SlidingWindow<string>;
    private readonly codeFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'otp_brute_force'>, state: ToolState) {
        super({
            id: 'otp_brute_force',
            displayName: 'OTP brute force',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.bySubject = state.window<string>('bySubject', config.windowMs, config.maxGuessesPerAccount * 4);
        this.byClient = state.window<string>('byClient', config.windowMs, config.maxGuessesPerClient * 4);
        this.codeFields = new Set(config.codeFields);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        if (!inRouteFilter(pathOf(context), this.config.routes) || !isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }

        // MFA happens mid-login, so the subject is the account if named, otherwise the half-authenticated session
        const subject = accountOf(context) ?? sessionKey(context);
        if (!subject) {
            return failure(this.tool, { reason: 'missing_account' });
        }

        const codeField = context.fields.find(field => this.codeFields.has(fieldLeaf(field.name)));
        const code = hashOf(String(codeField?.value ?? ''));
        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();

        // distinct codes, so a client resubmitting the same code (double click, retry) is not penalised
        const subjectGuesses = distinct(await this.bySubject.record(context.tenantId, hashOf(subject), code, now), value => value).size;
        const clientGuesses = distinct(await this.byClient.record(context.tenantId, context.clientIp, code, now), value => value).size;

        const { windowMs, maxGuessesPerAccount, maxGuessesPerClient } = this.config;
        if (subjectGuesses > maxGuessesPerAccount) {
            return violation(this.tool, { rule: 'too_many_guesses_for_account', guesses: subjectGuesses, limit: maxGuessesPerAccount, windowMs });
        }
        if (clientGuesses > maxGuessesPerClient) {
            return violation(this.tool, { rule: 'too_many_guesses_from_client', guesses: clientGuesses, limit: maxGuessesPerClient, windowMs });
        }
        return safe(this.tool);
    }
}
