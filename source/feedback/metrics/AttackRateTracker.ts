import { assertTenantId } from '../../shared/storage/tenant-id';

/**
 * Smoothing factors applied when the observation is above (`up`) or below (`down`) the current
 * average. `up > down` makes the rate react quickly to attacks but recover slowly, so an attacker
 * cannot dilute it with a burst of benign requests right before attacking.
 */
export interface AsymmetricAlpha {
    up: number;
    down: number;
}

/**
 * What one request contributes to feedback. Static-analysis blocks and errors are never observed.
 * `UNSAMPLED` requests passed static analysis but did not reach JEV: they count as benign for the
 * threshold signal and are ignored by the sampling signal.
 */
export type Observation = 'ATTACK' | 'BENIGN' | 'UNSAMPLED';

export interface AttackRates {
    /** Endpoint rate from JEV classifications only; drives sampling. */
    endpointSampling: number;
    /** Tenant rate from JEV classifications only; baseline for sampling. */
    tenantSampling: number;
    /** Tenant rate over every statically-eligible request; drives threshold tightening. */
    tenantThreshold: number;
}

interface TenantRates {
    sampling: number;
    threshold: number;
    endpoints: Map<string, number>;
}

export function asymmetricEwma(previous: number, observed: number, alpha: AsymmetricAlpha): number {
    const a = observed > previous ? alpha.up : alpha.down;
    return a * observed + (1 - a) * previous;
}

/**
 * In-memory, tenant-scoped attack-rate EWMAs. Endpoints must come from the active policy, not the
 * raw request path, otherwise arbitrary paths would grow this state without bound.
 */
export class AttackRateTracker {
    private readonly tenants = new Map<string, TenantRates>();

    constructor(private readonly alpha: AsymmetricAlpha) {
        for (const value of [alpha.up, alpha.down]) {
            if (!(value > 0 && value <= 1)) throw new Error('EWMA alpha must be in (0, 1]');
        }
    }

    /** Starts an endpoint at `seed` the first time it is seen; later calls are no-ops. */
    ensureEndpoint(tenantId: string, endpoint: string, seed: number): void {
        const tenant = this.tenant(tenantId);
        if (!tenant.endpoints.has(endpoint)) tenant.endpoints.set(endpoint, clamp01(seed));
    }

    observe(tenantId: string, endpoint: string, observation: Observation): void {
        const tenant = this.tenant(tenantId);
        const x = observation === 'ATTACK' ? 1 : 0;

        tenant.threshold = asymmetricEwma(tenant.threshold, x, this.alpha);
        if (observation === 'UNSAMPLED') return;

        tenant.sampling = asymmetricEwma(tenant.sampling, x, this.alpha);
        const endpointRate = tenant.endpoints.get(endpoint) ?? 0;
        tenant.endpoints.set(endpoint, asymmetricEwma(endpointRate, x, this.alpha));
    }

    rates(tenantId: string, endpoint: string): AttackRates {
        const tenant = this.tenant(tenantId);
        return {
            endpointSampling: tenant.endpoints.get(endpoint) ?? 0,
            tenantSampling: tenant.sampling,
            tenantThreshold: tenant.threshold,
        };
    }

    private tenant(tenantId: string): TenantRates {
        let tenant = this.tenants.get(tenantId);
        if (!tenant) {
            tenant = { sampling: 0, threshold: 0, endpoints: new Map() };
            this.tenants.set(assertTenantId(tenantId), tenant);
        }
        return tenant;
    }
}

function clamp01(value: number): number {
    return Math.min(1, Math.max(0, value));
}
