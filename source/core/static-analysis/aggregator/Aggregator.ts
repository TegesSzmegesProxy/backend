import { ToolResult } from '@tessera/core/static-analysis/shared';

export interface StaticVerdict {
    verdict: 'SAFE' | 'SUSPICIOUS' | 'POLICY_VIOLATION' | 'ERROR';
    results: ToolResult[];
    evidence: unknown;
}

export class Aggregator {
    aggregate(results: ToolResult[]): StaticVerdict {
        const suspicious = [];

        const unsafe = results.filter(r => r.verdict !== 'SAFE');
        
        for (const result of unsafe) {
            if (result.verdict === 'POLICY_VIOLATION') {
                return {
                    verdict: 'POLICY_VIOLATION',
                    results: unsafe,
                    evidence: result.evidence,
                }
            } else if (result.verdict === 'SUSPICIOUS') {
                suspicious.push(result);
            } else if (result.verdict === 'ERROR') {
                return {
                    verdict: 'ERROR',
                    results: [result],
                    evidence: result.evidence,
                }
            }
        }

        if (suspicious.length === 0) {
            return {
                verdict: 'SAFE',
                results: [],
                evidence: undefined,
            }
        }

        return {
            verdict: 'SUSPICIOUS',
            results: suspicious,
            evidence: suspicious.map(s => s.evidence),
        }
    }
}