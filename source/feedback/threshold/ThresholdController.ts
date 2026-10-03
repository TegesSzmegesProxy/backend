import type { ThresholdConfig } from '@tessera/shared/contracts';

/** The part of a JEV verdict the thresholds read. */
export interface JevScore {
    attackProbability: number;
}

export interface EffectiveThresholds {
    attackProbabilityThreshold: number;
}

export interface ThresholdTuning {
    /** Steepness of the saturating curve: higher reaches `attackProbabilityFloor` at a lower attack rate. */
    sensitivity: number;
}

/** JEV returned something the thresholds cannot be applied to. Callers handle it like an unavailable JEV. */
export class InvalidJevResultError extends Error {}

/**
 * Tighten-only thresholds. The effective attack probability threshold moves from the user's value toward
 * `attackProbabilityFloor` as the tenant attack rate rises, and back as it falls; it never exceeds the
 * user's value. Locked configs are returned unchanged.
 */
export class ThresholdController {
    constructor(private readonly tuning: ThresholdTuning) {
        if (!(tuning.sensitivity > 0)) throw new Error('sensitivity must be positive');
    }

    effective(config: ThresholdConfig, tenantAttackRate: number): EffectiveThresholds {
        assertThresholdConfig(config);
        const { attackProbabilityThreshold, attackProbabilityFloor } = config;
        if (config.locked) return { attackProbabilityThreshold };

        const tightening = 1 - Math.exp(-this.tuning.sensitivity * tenantAttackRate);
        return {
            attackProbabilityThreshold:
                attackProbabilityThreshold - (attackProbabilityThreshold - attackProbabilityFloor) * tightening,
        };
    }

    /** `ATTACK` only when the attack probability is strictly above the effective threshold. */
    classify(result: JevScore, thresholds: EffectiveThresholds): 'ATTACK' | 'BENIGN' {
        // NaN compares false against any threshold, which would silently read as BENIGN.
        const p = result.attackProbability;
        if (!Number.isFinite(p) || p < 0 || p > 1) {
            throw new InvalidJevResultError('JEV attack probability must be a number from 0 to 1');
        }
        return p > thresholds.attackProbabilityThreshold ? 'ATTACK' : 'BENIGN';
    }
}

/** The comparison is strict, so a threshold of 1 could never be exceeded and would never block. */
function assertThresholdConfig({ attackProbabilityThreshold: t, attackProbabilityFloor: floor }: ThresholdConfig): void {
    if (!(t >= 0 && t < 1)) {
        throw new RangeError(`attackProbabilityThreshold ${t} must be at least 0 and below 1`);
    }
    if (!(floor >= 0 && floor <= t)) {
        throw new RangeError(`attackProbabilityFloor ${floor} must be in [0, attackProbabilityThreshold]`);
    }
}
