import type { SamplingConfig } from '@tessera/shared/contracts';
import type { AttackRates } from '../metrics';

export interface SamplingTuning {
    /** Share of the endpoint rate in the blended signal; the tenant rate gets the rest. */
    endpointWeight: number;
    /** Steepness of the saturating curve: higher reaches `maxN` at a lower attack rate. */
    sensitivity: number;
}

/**
 * Maps smoothed attack rates to a sampling probability within `[minN, maxN]`:
 * `N = minN + (maxN - minN) * (1 - e^(-k * s))`, `s = w * endpoint + (1 - w) * tenant`.
 * N is computed from the signal each time rather than stepped, so it cannot drift out of bounds.
 */
export class SamplingController {
    constructor(private readonly tuning: SamplingTuning) {
        if (!(tuning.endpointWeight > 0 && tuning.endpointWeight <= 1)) {
            throw new Error('endpointWeight must be in (0, 1]');
        }
        if (!(tuning.sensitivity > 0)) throw new Error('sensitivity must be positive');
    }

    probability(config: SamplingConfig, rates: AttackRates): number {
        assertSamplingConfig(config);
        const { endpointWeight: w, sensitivity: k } = this.tuning;
        const signal = w * rates.endpointSampling + (1 - w) * rates.tenantSampling;
        const n = config.minN + (config.maxN - config.minN) * (1 - Math.exp(-k * signal));
        return Math.min(config.maxN, Math.max(config.minN, n));
    }

    /**
     * Endpoint rate that makes `probability` return the user's initial `probabilityN` while the
     * tenant rate is zero. The rate then decays toward 0 (and N toward `minN`) under benign traffic.
     */
    seedRate(config: SamplingConfig): number {
        assertSamplingConfig(config);
        const span = config.maxN - config.minN;
        if (span === 0) return 0;
        const fraction = Math.min(0.999, (config.probabilityN - config.minN) / span);
        const signal = -Math.log(1 - fraction) / this.tuning.sensitivity;
        return Math.min(1, signal / this.tuning.endpointWeight);
    }
}

function assertSamplingConfig({ probabilityN, minN, maxN }: SamplingConfig): void {
    // minN > 0 keeps JEV observations flowing; with 0 an endpoint could never raise its own N.
    if (!(minN > 0 && minN <= probabilityN && probabilityN <= maxN && maxN <= 1)) {
        throw new Error('Sampling config must satisfy 0 < minN <= probabilityN <= maxN <= 1');
    }
}
