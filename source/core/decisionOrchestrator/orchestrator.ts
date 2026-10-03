import type { NormalizedRequest, SamplingConfig, ThresholdConfig } from "@tessera/shared/contracts";
import type { StaticVerdict } from "@tessera/core/static-analysis/aggregator";
import type { DynamicVerdict } from "@tessera/core/jev/client";
import { InvalidJevResultError } from "@tessera/feedback";
import type { EffectiveThresholds, Observation } from "@tessera/feedback";

export type Action = "ALLOW" | "BLOCK";
export type Classification = "ATTACK" | "BENIGN";

/** A JEV verdict together with the classification the thresholds gave it. */
export interface JevResult extends DynamicVerdict {
    verdict: Classification;
    /** The effective attack probability threshold the verdict was compared against. */
    threshold: number;
}

export interface Decision {
    action: Action;
    reason: string;
    staticVerdict: StaticVerdict;
    /** True only when the sampler picked this static-SAFE request for JEV. Suspicious requests always go to JEV and are not sampled. */
    sampled: boolean;
    jev?: JevResult;
}

/** The only part of the JEV client the orchestrator depends on. */
export interface Jev {
    createVerdict(request: NormalizedRequest, staticAnalysis: StaticVerdict): Promise<DynamicVerdict>;
}

/** Adaptive N, effective thresholds and attack-rate feedback; implemented by `AdaptiveControl`. */
export interface Adaptive {
    samplingProbability(tenantId: string, endpoint: string, config: SamplingConfig): number;
    effectiveThresholds(tenantId: string, endpoint: string, config: ThresholdConfig): EffectiveThresholds;
    classify(result: DynamicVerdict, thresholds: EffectiveThresholds): Classification;
    observe(tenantId: string, endpoint: string, observation: Observation): void;
}

/** Draws whether a request goes to JEV; implemented by `Sampler`. */
export interface Sampling {
    shouldSample(verdict: StaticVerdict["verdict"], probabilityN: number): boolean;
}

/** The tenant's user-set sampling and threshold configuration for an endpoint. */
export interface RuntimeConfig {
    sampling: SamplingConfig;
    threshold: ThresholdConfig;
}

export interface DecisionDependencies {
    jev: Jev;
    adaptive: Adaptive;
    sampler: Sampling;
    configFor(tenantId: string, endpoint: string): RuntimeConfig;
}

export interface DecisionConfig {
    staticAnalysisError: Action;
    suspiciousWhenJevUnavailable: Action;
    /** Applies when a sampled static-SAFE request cannot be classified by JEV. */
    sampledWhenJevUnavailable: Action;
}

type JevSubject = "suspicious" | "sampled";

export class DecisionOrchestrator {
    constructor(
        private readonly deps: DecisionDependencies,
        private readonly config: DecisionConfig
    ) {}

    async orchestrate(request: NormalizedRequest, staticVerdict: StaticVerdict): Promise<Decision> {
        switch (staticVerdict.verdict) {
            case "POLICY_VIOLATION":
                return { action: "BLOCK", reason: "static policy violation", staticVerdict, sampled: false };
            case "ERROR":
                return {
                    action: this.config.staticAnalysisError,
                    reason: "static analysis error",
                    staticVerdict,
                    sampled: false,
                };
            case "SUSPICIOUS":
                return this.classify(request, staticVerdict, "suspicious", false);
            case "SAFE": {
                const { tenantId, endpoint } = request;
                const n = this.deps.adaptive.samplingProbability(tenantId, endpoint, this.deps.configFor(tenantId, endpoint).sampling);
                if (!this.deps.sampler.shouldSample("SAFE", n)) {
                    // Counts as benign for threshold tightening only; it carries no sampling signal.
                    this.deps.adaptive.observe(tenantId, endpoint, "UNSAMPLED");
                    return { action: "ALLOW", reason: "static analysis safe, not sampled", staticVerdict, sampled: false };
                }
                return this.classify(request, staticVerdict, "sampled", true);
            }
        }
    }

    private async classify(
        request: NormalizedRequest,
        staticVerdict: StaticVerdict,
        subject: JevSubject,
        sampled: boolean
    ): Promise<Decision> {
        let jev: DynamicVerdict;
        try {
            jev = await this.deps.jev.createVerdict(request, staticVerdict);
        } catch {
            return this.jevFailed(subject, "JEV unavailable", staticVerdict, sampled);
        }

        const { tenantId, endpoint } = request;
        const thresholds = this.deps.adaptive.effectiveThresholds(tenantId, endpoint, this.deps.configFor(tenantId, endpoint).threshold);
        let classification: Classification;
        try {
            classification = this.deps.adaptive.classify(jev, thresholds);
        } catch (error) {
            if (error instanceof InvalidJevResultError) {
                return this.jevFailed(subject, "JEV result invalid", staticVerdict, sampled);
            }
            throw error;
        }

        this.deps.adaptive.observe(tenantId, endpoint, classification);

        const threshold = thresholds.attackProbabilityThreshold;
        const detail = `p=${jev.attackProbability.toFixed(2)}, threshold=${threshold.toFixed(2)}`;
        const attack = classification === "ATTACK";
        return {
            action: attack ? "BLOCK" : "ALLOW",
            reason: attack ? `JEV classified as attack (${detail})` : `JEV did not classify as attack (${detail})`,
            staticVerdict,
            sampled,
            jev: { ...jev, verdict: classification, threshold },
        };
    }

    /** No classification exists, so nothing is fed back to the attack rate. */
    private jevFailed(subject: JevSubject, failure: string, staticVerdict: StaticVerdict, sampled: boolean): Decision {
        return {
            action:
                subject === "suspicious"
                    ? this.config.suspiciousWhenJevUnavailable
                    : this.config.sampledWhenJevUnavailable,
            reason: `${subject} and ${failure}`,
            staticVerdict,
            sampled,
        };
    }
}
