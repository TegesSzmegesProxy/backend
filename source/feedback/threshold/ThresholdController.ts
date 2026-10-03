import type { ThresholdConfig } from '@tessera/shared/contracts';

export interface JevScore {
    score: number;
    confidence: number;
}

export interface EffectiveThresholds {
    maliciousScoreThreshold: number;
    confidenceThreshold: number;
}

export interface ThresholdTuning {
    /** Steepness of the saturating curve: higher reaches `confidenceFloor` at a lower attack rate. */
    sensitivity: number;
}

/**
 * Tighten-only thresholds. The effective confidence threshold moves from the user's value toward
 * `confidenceFloor` as the tenant attack rate rises, and back as it falls; it never exceeds the
 * user's value. The score threshold is never adapted. Locked configs are returned unchanged.
 */
export class ThresholdController {
    constructor(private readonly tuning: ThresholdTuning) {
        if (!(tuning.sensitivity > 0)) throw new Error('sensitivity must be positive');
    }

    effective(config: ThresholdConfig, tenantAttackRate: number): EffectiveThresholds {
        if (!(config.confidenceFloor >= 0 && config.confidenceFloor <= config.confidenceThreshold)) {
            throw new Error('confidenceFloor must be in [0, confidenceThreshold]');
        }
        const { maliciousScoreThreshold, confidenceThreshold, confidenceFloor } = config;
        if (config.locked) return { maliciousScoreThreshold, confidenceThreshold };

        const tightening = 1 - Math.exp(-this.tuning.sensitivity * tenantAttackRate);
        return {
            maliciousScoreThreshold,
            confidenceThreshold: confidenceThreshold - (confidenceThreshold - confidenceFloor) * tightening,
        };
    }

    /** `ATTACK` only when both the score and the confidence exceed their thresholds. */
    classify(result: JevScore, thresholds: EffectiveThresholds): 'ATTACK' | 'BENIGN' {
        if (!Number.isFinite(result.score) || !Number.isFinite(result.confidence)) {
            throw new Error('JEV returned a non-numeric score or confidence');
        }
        return result.score > thresholds.maliciousScoreThreshold &&
            result.confidence > thresholds.confidenceThreshold
            ? 'ATTACK'
            : 'BENIGN';
    }
}
