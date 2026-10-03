import type { SamplingConfig, ThresholdConfig } from '@tessera/shared/contracts';
import { AttackRateTracker, type AsymmetricAlpha, type Observation } from './metrics';
import { SamplingController, type SamplingTuning } from './sampler';
import { ThresholdController, type EffectiveThresholds, type JevScore, type ThresholdTuning } from './threshold';

export interface AdaptiveTuning {
    alpha: AsymmetricAlpha;
    sampling: SamplingTuning;
    threshold: ThresholdTuning;
}

export const DEFAULT_ADAPTIVE_TUNING: AdaptiveTuning = {
    alpha: { up: 0.3, down: 0.02 },
    sampling: { endpointWeight: 0.7, sensitivity: 5 },
    threshold: { sensitivity: 5 },
};

/**
 * Proxy-side adaptive control: reads N and effective thresholds for the request path, and takes
 * feedback after the decision. Never call `observe` for static policy violations or errors.
 */
export class AdaptiveControl {
    private readonly rates: AttackRateTracker;
    private readonly sampler: SamplingController;
    private readonly thresholds: ThresholdController;

    constructor(tuning: AdaptiveTuning = DEFAULT_ADAPTIVE_TUNING) {
        this.rates = new AttackRateTracker(tuning.alpha);
        this.sampler = new SamplingController(tuning.sampling);
        this.thresholds = new ThresholdController(tuning.threshold);
    }

    samplingProbability(tenantId: string, endpoint: string, config: SamplingConfig): number {
        this.rates.ensureEndpoint(tenantId, endpoint, this.sampler.seedRate(config));
        return this.sampler.probability(config, this.rates.rates(tenantId, endpoint));
    }

    effectiveThresholds(tenantId: string, endpoint: string, config: ThresholdConfig): EffectiveThresholds {
        return this.thresholds.effective(config, this.rates.rates(tenantId, endpoint).tenantThreshold);
    }

    classify(result: JevScore, thresholds: EffectiveThresholds): 'ATTACK' | 'BENIGN' {
        return this.thresholds.classify(result, thresholds);
    }

    observe(tenantId: string, endpoint: string, observation: Observation): void {
        this.rates.observe(tenantId, endpoint, observation);
    }
}
