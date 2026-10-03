export interface SamplingConfig {
    probabilityN: number;
    minN: number;
    maxN: number;
}

export interface ThresholdConfig {
    maliciousScoreThreshold: number;
    confidenceThreshold: number;
    confidenceFloor: number;
    locked: boolean;
}
