import type { StaticVerdict } from '../static-analysis/aggregator';

/**
 * Decides whether a statically-eligible request goes to JEV. Suspicious requests always do; safe
 * ones with probability N. Blocked or failed static verdicts must be handled before sampling.
 */
export class Sampler {
    constructor(private readonly random: () => number = Math.random) {}

    shouldSample(verdict: StaticVerdict['verdict'], probabilityN: number): boolean {
        if (verdict === 'SUSPICIOUS') return true;
        if (verdict === 'SAFE') return this.random() < probabilityN;
        throw new Error(`Static verdict ${verdict} must not reach sampling`);
    }
}
