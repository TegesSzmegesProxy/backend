import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState } from '@tessera/core/static-analysis/shared';

interface Sighting {
    at: number;
    endpoint: string;
    ids: string[]; // integer-valued fields of the request, used to spot enumeration
}

export default class SequenceAnalysis extends Tool<ToolContextType.Full> {
    private static readonly MAX_HISTORY = 200; // per client

    // (Redis, per tenant) client -> recent requests, oldest first.
    private readonly history: SlidingWindow<Omit<Sighting, 'at'>>;

    constructor(private readonly config: ToolConfig<'sequence_analysis'>, state: ToolState) {
        super({
            id: 'sequence_analysis',
            displayName: 'Sequence analysis',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        this.history = state.window('history', config.windowMs, SequenceAnalysis.MAX_HISTORY);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        // scanning: many different endpoints in one window; enumeration: consecutive integer values on one endpoint
        const { windowMs, maxDistinctEndpoints, minSequence } = this.config;

        if (!context.clientIp || !context.tenantId) {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { reason: 'missing_client_identity' },
            };
        }

        const now = Date.now();
        // ponytail: assumes the pipeline runs each tool once per request; a retry would count twice.
        const recent: Sighting[] = (await this.history.record(context.tenantId, context.clientIp, {
            endpoint: context.endpoint,
            ids: SequenceAnalysis.integerValues(context),
        }, now)).map(event => ({ at: event.at, ...event.value }));

        const distinct = new Set(recent.map(s => s.endpoint)).size;
        const run = SequenceAnalysis.longestRun(recent.filter(s => s.endpoint === context.endpoint));

        const findings: string[] = [];
        if (distinct > maxDistinctEndpoints) findings.push('endpoint_scan');
        if (run >= minSequence) findings.push('sequential_id_enumeration');

        if (findings.length === 0) {
            return { tool: this.tool, status: 'SUCCESS', verdict: 'SAFE', evidence: undefined };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SUSPICIOUS',
            evidence: { findings, distinctEndpoints: distinct, longestSequence: run, windowMs },
        };
    }

    // Values of fields that are non-negative integers, so "id=7" then "id=8" can be recognised as a walk.
    private static integerValues(request: NormalizedRequest): string[] {
        return request.fields
            .filter(f => typeof f.value === 'number' || (typeof f.value === 'string' && /^\d{1,15}$/.test(f.value)))
            .map(f => `${f.name}=${f.value}`);
    }

    // Longest chain of requests where some field's integer value goes up by exactly 1 (or down by exactly 1).
    private static longestRun(sightings: Sighting[]): number {
        let best = sightings.length > 0 ? 1 : 0;
        // field name -> [current direction-agnostic run length, last value, direction]
        const runs = new Map<string, { length: number; last: number; step: number }>();

        for (const { ids } of sightings) {
            for (const id of ids) {
                const [name, raw] = id.split('=');
                const value = Number(raw);
                const prev = runs.get(name);
                const step = prev ? value - prev.last : 0;
                if (prev && Math.abs(step) === 1 && (prev.step === 0 || prev.step === step)) {
                    prev.length++;
                    prev.last = value;
                    prev.step = step;
                    best = Math.max(best, prev.length);
                } else {
                    runs.set(name, { length: 1, last: value, step: 0 });
                }
            }
        }
        return best;
    }
}
