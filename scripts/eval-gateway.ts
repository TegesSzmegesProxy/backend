/**
 * A minimal Tessera data plane for the evaluation: the real normalizer, static analysis, JEV client, adaptive
 * control and decision orchestrator in front of the mock upstream. Allowed requests are forwarded; blocked ones
 * get a 403. Response headers carry what the eval needs to score the case.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import replyFrom from '@fastify/reply-from';
import { TypeSafeClient } from '@typesafe-ai/sdk';
import { Normalizer } from '../source/edge/normalizer';
import { Runner } from '../source/core/static-analysis/runner';
import { Aggregator } from '../source/core/static-analysis/aggregator';
import { JevClient } from '../source/core/jev/client';
import { DecisionOrchestrator } from '../source/core/decisionOrchestrator';
import { Sampler } from '../source/core/sampling';
import { AdaptiveControl } from '../source/feedback';
import { EVAL_TENANT, applyPolicy, planFor, type Fixture } from '../tests/fixtures/jevCases';

export interface GatewayOptions {
    upstreamUrl: string;
    fixture: Fixture;
    /** Probability above which JEV results block. */
    threshold: number;
    /** Lets attack rates tighten the threshold toward 0.5, as in production. Off by default so the eval is stationary. */
    adaptive?: boolean;
}

export async function startGateway(options: GatewayOptions): Promise<{ app: FastifyInstance; url: string }> {
    const { upstreamUrl, fixture, threshold, adaptive = false } = options;
    const app = Fastify({ bodyLimit: 8 * 1024 * 1024, trustProxy: true });
    await app.register(replyFrom, { base: upstreamUrl });

    const normalizer = new Normalizer();
    const runner = new Runner();
    const aggregator = new Aggregator();
    const orchestrator = new DecisionOrchestrator(
        {
            jev: new JevClient(new TypeSafeClient({})),
            adaptive: new AdaptiveControl(),
            sampler: new Sampler(),
            configFor: () => ({
                sampling: { probabilityN: 1, minN: 1, maxN: 1 },
                threshold: { attackProbabilityThreshold: threshold, attackProbabilityFloor: Math.min(0.5, threshold), locked: !adaptive },
            }),
        },
        // Failures must show up as errors in the eval, never as a quiet ALLOW.
        { staticAnalysisError: 'BLOCK', suspiciousWhenJevUnavailable: 'BLOCK', sampledWhenJevUnavailable: 'BLOCK' }
    );

    app.route({
        method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        url: '/*',
        handler: async (request, reply) => {
            const parsed = normalizer.normalize(request, EVAL_TENANT);
            const policy = fixture.endpoints[parsed.endpoint];
            const normalized = policy ? applyPolicy(parsed, policy) : parsed;
            const verdict = aggregator.aggregate(runner.run(normalized, policy ? planFor(normalized, policy) : []));
            const decision = await orchestrator.orchestrate(normalized, verdict);

            reply.header('x-tessera-static', verdict.verdict);
            reply.header('x-tessera-reason', decision.reason);
            if (decision.jev) {
                reply.header('x-tessera-p', String(decision.jev.attackProbability));
                reply.header('x-tessera-severity', String(decision.jev.score));
            }
            if (decision.action === 'BLOCK') return reply.code(403).send({ requestId: normalized.requestId });
            return reply.from(request.raw.url ?? '/');
        },
    });

    const url = await app.listen({ port: 0, host: '127.0.0.1' });
    return { app, url };
}
