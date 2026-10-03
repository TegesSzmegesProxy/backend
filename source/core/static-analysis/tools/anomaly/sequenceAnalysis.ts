import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface Sighting {
    at: number;
    endpoint: string;
    ids: string[]; // integer-valued fields of the request, used to spot enumeration
}

export default class SequenceAnalysis extends Tool<ToolContextType.Full> {
    // hard-coded until we have enough infrastructure to support tool configuration
    private static readonly WINDOW_MS = 60_000;
    private static readonly MAX_DISTINCT_ENDPOINTS = 15; // scanning: many different endpoints in one window
    private static readonly MIN_SEQUENCE = 5; // enumeration: this many consecutive integer values on one endpoint
    private static readonly MAX_HISTORY = 200; // per client
    private static readonly MAX_CLIENTS = 50_000;

    // client key -> recent requests, oldest first. Static so state is shared however often the tool is instantiated.
    private static readonly history = new Map<string, Sighting[]>();

    constructor() {
        super({
            id: 'sequence_analysis',
            displayName: 'Sequence analysis',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const { WINDOW_MS, MAX_DISTINCT_ENDPOINTS, MIN_SEQUENCE } = SequenceAnalysis;

        if (!context.clientIp || !context.tenantId) {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { reason: 'missing_client_identity' },
            };
        }

        const now = Date.now();
        const key = `${context.tenantId}|${context.clientIp}`;
        const recent = (SequenceAnalysis.history.get(key) ?? []).filter(s => now - s.at <= WINDOW_MS);

        // ponytail: assumes the pipeline runs each tool once per request; a retry would count twice.
        recent.push({ at: now, endpoint: context.endpoint, ids: SequenceAnalysis.integerValues(context) });
        if (recent.length > SequenceAnalysis.MAX_HISTORY) {
            recent.shift();
        }

        // delete + set moves the client to the end of the Map, so eviction drops the least recently active one
        SequenceAnalysis.history.delete(key);
        SequenceAnalysis.history.set(key, recent);
        while (SequenceAnalysis.history.size > SequenceAnalysis.MAX_CLIENTS) {
            const oldest = SequenceAnalysis.history.keys().next();
            if (oldest.done) break;
            SequenceAnalysis.history.delete(oldest.value);
        }

        const distinct = new Set(recent.map(s => s.endpoint)).size;
        const run = SequenceAnalysis.longestRun(recent.filter(s => s.endpoint === context.endpoint));

        const findings: string[] = [];
        if (distinct > MAX_DISTINCT_ENDPOINTS) findings.push('endpoint_scan');
        if (run >= MIN_SEQUENCE) findings.push('sequential_id_enumeration');

        if (findings.length === 0) {
            return { tool: this.tool, status: 'SUCCESS', verdict: 'SAFE', evidence: undefined };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SUSPICIOUS',
            evidence: { findings, distinctEndpoints: distinct, longestSequence: run, windowMs: WINDOW_MS },
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

    // For tests.
    static reset(): void {
        SequenceAnalysis.history.clear();
    }
}
