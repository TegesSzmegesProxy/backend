import { createHash } from 'node:crypto';
import { NormalizedRequest } from '@tessera/shared/contracts';
import { TypeSafeClient } from '@typesafe-ai/sdk';
import { encode } from '@toon-format/toon';
import { StaticVerdict } from '../static-analysis/aggregator';
import { JEV_ATTACK_QUESTION, JEV_SEVERITY_QUESTION } from './prompt';

export interface DynamicVerdict {
    /** Expected severity level (0 benign to 3 critical); for display, not enforcement. */
    score: number;
    /** Probability that the request is an attack (0 to 1). This decides enforcement. */
    attackProbability: number;
    /** How decisive the result is on either side (0 at 50/50, 1 when sure); for logs and review, not enforcement. */
    confidence: number;
}

/** The part of the TypeSafe SDK JEV uses, so tests can pass a fake. */
export type JevModel = Pick<TypeSafeClient, 'systemOne'>;

/** Where verdicts are cached; in production a tenant-scoped `TenantRedis` namespace. */
export interface VerdictStore {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttlSeconds?: number): Promise<void>;
}

/** Only what JEV needs to judge the request. Identifiers, IPs, headers and static verdict words are left out. */
interface JevState {
    endpoint: string;
    fields: { name: string; location: string; value: unknown }[];
    files?: { field: string; filename: string; contentType?: string; size: number }[];
    patternMatches?: { field?: string; check: string; rules: unknown }[];
    patternMatchNote?: string;
}

const PATTERN_MATCH_NOTE = 'Keyword/regex pre-filter. Matches are frequent on ordinary text and are not findings.';
const VERDICT_CACHE_TTL_SECONDS = 60 * 60 * 24;

export class JevClient {
    constructor(
        private readonly model: JevModel,
        private readonly cache: VerdictStore
    ) {}

    // The verdict is a function of exactly what the model sees, so the key is a hash of that state.
    // Keying on less (e.g. the body alone) would let one cached verdict answer for a different request.
    private cacheKey(state: string): string {
        return createHash('sha256').update(state).digest('hex');
    }

    // Fire-and-forget: the cache is non-authoritative, so a failed write must not fail the verdict.
    private storeVerdict(key: string, verdict: DynamicVerdict) {
        this.cache.set(key, JSON.stringify(verdict), VERDICT_CACHE_TTL_SECONDS)
            .catch(err => console.error('Storing to cache failed', err));
    }

    // Any cache failure, unreadable entry or out-of-range value counts as a miss, so the model decides instead.
    private async checkVerdict(key: string): Promise<DynamicVerdict | undefined> {
        let json: Record<string, unknown>;
        try {
            const verdict = await this.cache.get(key);
            if (verdict === null) return undefined;
            json = JSON.parse(verdict);
        } catch (err) {
            console.warn('Reading from cache failed', err);
            return undefined;
        }
        if (json === null || typeof json !== 'object') return undefined;

        const { score, attackProbability, confidence } = json;
        if (typeof score !== 'number' || typeof attackProbability !== 'number' || typeof confidence !== 'number') return;
        if (!Number.isFinite(score) || !Number.isFinite(confidence)) return;
        if (!Number.isFinite(attackProbability) || attackProbability < 0 || attackProbability > 1) return;

        return {
            score,
            attackProbability,
            confidence,
        };
    }

    async createVerdict(request: NormalizedRequest, staticAnalysis: StaticVerdict): Promise<DynamicVerdict> {
        const state = encode(this.buildState(request, staticAnalysis));
        const key = this.cacheKey(state);
        const previousVerdict = await this.checkVerdict(key);
        console.log(previousVerdict ? `JEV cache hit for ${request.requestId} (endpoint ${request.endpoint})` : `JEV cache miss for ${request.requestId} (endpoint ${request.endpoint})`);
        if (previousVerdict !== undefined) return previousVerdict;

        const response = await this.model.systemOne({
            state,
            questions: {
                attack: JEV_ATTACK_QUESTION,
                severity: JEV_SEVERITY_QUESTION,
            },
        });

        const attackProbability = response.answers.attack.noul;
        if (!Number.isFinite(attackProbability) || attackProbability < 0 || attackProbability > 1) {
            throw new RangeError(`JEV attack probability ${attackProbability} is not between 0 and 1`);
        }

        const verdict = {
            score: response.answers.severity.score,
            attackProbability,
            confidence: Math.abs(2 * attackProbability - 1),
        };

        console.log(`JEV verdict for ${request.requestId} (endpoint ${request.endpoint}):`, verdict);

        this.storeVerdict(key, verdict);

        return verdict;
    }

    private buildState(request: NormalizedRequest, staticAnalysis: StaticVerdict): JevState {
        const state: JevState = {
            endpoint: request.endpoint,
            fields: request.fields.map(({ name, location, value }) => ({ name, location, value })),
        };
        if (request.files.length > 0) {
            state.files = request.files.map(({ field, filename, contentType, size }) => ({ field, filename, contentType, size }));
        }

        const matches = staticAnalysis.results
            .filter((result) => result.verdict === 'SUSPICIOUS')
            .map((result) => ({ field: result.target, check: result.tool, rules: result.evidence }));
        if (matches.length > 0) {
            state.patternMatches = matches;
            state.patternMatchNote = PATTERN_MATCH_NOTE;
        }
        return state;
    }
}
