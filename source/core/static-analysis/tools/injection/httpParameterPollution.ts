import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, cookiesOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface Occurrence {
    location: string;
    value: string;
}

export default class HttpParameterPollution extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'http_parameter_pollution',
            displayName: 'HTTP parameter pollution',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // parameter name -> every value it has, wherever it appears
        const occurrences = new Map<string, Occurrence[]>();
        const add = (name: string, location: string, value: unknown): void => {
            if (value === null || value === undefined || typeof value === 'object') return;
            const list = occurrences.get(name) ?? [];
            list.push({ location, value: String(value) });
            occurrences.set(name, list);
        };

        for (const field of context.fields) {
            // the normalizer flattens "?id=1&id=2" into "id.0" and "id.1"; fold them back into "id"
            const name = field.location === 'query' ? field.name.replace(/\.\d+$/, '') : field.name;
            add(name, field.location, field.value);
        }
        for (const [name, value] of cookiesOf(context)) {
            add(name, 'cookie', value);
        }

        const findings: { parameter: string; locations: string[]; distinctValues: number; rule: string }[] = [];
        for (const [name, list] of occurrences) {
            if (list.length < 2 || name.endsWith('[]')) continue; // "tags[]" declares an array on purpose
            const values = new Set(list.map(occurrence => occurrence.value));
            if (values.size < 2) continue; // repeated with the same value is harmless

            const locations = [...new Set(list.map(occurrence => occurrence.location))];
            findings.push({
                parameter: clip(name, 50),
                locations,
                distinctValues: values.size,
                // different layers (WAF, framework, backend) pick first, last, or join: that's the bypass
                rule: locations.length > 1 ? 'conflicting_values_across_locations' : 'duplicate_parameter_with_conflicting_values',
            });
        }

        return findings.length > 0 ? suspicious(this.tool, { findings: findings.slice(0, 10) }) : safe(this.tool);
    }
}
