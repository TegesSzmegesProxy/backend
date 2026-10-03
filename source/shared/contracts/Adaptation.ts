export interface SamplingConfig {
    probabilityN: number;
    minN: number;
    maxN: number;
}

export interface ThresholdConfig {
    /** A JEV result is an ATTACK when its attack probability is strictly above the effective threshold. */
    attackProbabilityThreshold: number;
    /** Lowest value the effective threshold may tighten to under attack (0 to attackProbabilityThreshold). */
    attackProbabilityFloor: number;
    /** Locked thresholds are never adapted. */
    locked: boolean;
}
