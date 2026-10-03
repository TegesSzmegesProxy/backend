import { NormalizedRequest } from '@tessera/shared/contracts';
import { TypeSafeClient } from '@typesafe-ai/sdk';
import { encode } from '@toon-format/toon';
import { StaticVerdict } from '../static-analysis/aggregator';
import { JEV_ATTACK_QUESTION, JEV_SEVERITY_QUESTION } from './prompt';
import { Normalizer } from '@tessera/edge/normalizer';

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

export class JevClient {
    constructor(
        private readonly model: JevModel,
        private readonly cache: VerdictStore
    ) {}

    private getRequestKey(request: NormalizedRequest) {
        return `${request.endpoint}:${Normalizer.hashRequestBody(request.body)}`;
    }

    private storeVerdict(request: NormalizedRequest, verdict: DynamicVerdict) {
        this.cache.set(this.getRequestKey(request), JSON.stringify(verdict), 60 * 60 * 24);
    }

    private async checkVerdict(request: NormalizedRequest): Promise<DynamicVerdict | undefined> {
        const verdict = await this.cache.get(this.getRequestKey(request));
        if (verdict === null) return undefined;

        const json = JSON.parse(verdict);
        const score = json['score'];
        const attackProbability = json['attackProbability'];
        const confidence = json['confidence'];

        if (score === undefined || attackProbability === undefined || confidence === undefined) return;
        if (typeof score !== 'number' || typeof attackProbability !== 'number' || typeof confidence !== 'number') return;
        if (isNaN(score) || isNaN(attackProbability) || isNaN(confidence)) return;

        return {
            score,
            attackProbability,
            confidence,
        };
    }

    async createVerdict(request: NormalizedRequest, staticAnalysis: StaticVerdict): Promise<DynamicVerdict> {
        const previousVerdict = await this.checkVerdict(request);
        if (previousVerdict !== undefined) return previousVerdict;
        
        const response = await this.model.systemOne({
            state: encode(this.buildState(request, staticAnalysis)),
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

        this.storeVerdict(request, verdict);

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
