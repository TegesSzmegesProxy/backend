import { NormalizedRequest } from '@tessera/shared/contracts';
import { score as mscore, TypeSafeClient, TypeSafeClientConfig } from '@typesafe-ai/sdk';
import { StaticVerdict } from '../static-analysis/aggregator';
import { JEV_CRITERIA, JEV_PROMPT } from './prompt';
import { encode } from '@toon-format/toon';

export interface DynamicVerdict {
    score: number;
    confidence: number;
}

export class JevClient {
    private client: TypeSafeClient;

    constructor (config: TypeSafeClientConfig) {
        this.client = new TypeSafeClient(config);
    }

    private createRequestTOON(request: NormalizedRequest, staticAnalysis: StaticVerdict) {
        return encode({
            request,
            results: staticAnalysis,
        });
    }

    async createVerdict(request: NormalizedRequest, staticAnalysis: StaticVerdict): Promise<DynamicVerdict> {
        const toon = this.createRequestTOON(request, staticAnalysis);

        const response = await this.client.systemOne({
            state: { document: toon },
            questions: {
                risk: mscore(JEV_PROMPT, JEV_CRITERIA),
            }
        });

        const { score, confidence } = response.answers.risk;

        return {
            score,
            confidence
        }
    }
}