import { NormalizedRequest } from '@tessera/shared/contracts';
import {
    Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, header, isStateChanging, methodOf, safe, suspicious, violation,
} from '@tessera/core/static-analysis/shared';

const OVERRIDE_HEADERS = ['x-http-method-override', 'x-method-override', 'x-http-method'];
const OVERRIDE_FIELDS = new Set(['method', 'httpmethod']); // "_method" folds to "method"
const DANGEROUS = new Set(['TRACE', 'TRACK', 'CONNECT', 'DEBUG']);

export default class MethodOverride extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'method_override',
            displayName: 'HTTP method override',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const method = methodOf(context);
        const overrides: { source: string; value: string }[] = [];

        for (const name of OVERRIDE_HEADERS) {
            const value = header(context, name);
            if (value !== undefined) overrides.push({ source: `header:${name}`, value });
        }
        for (const field of context.fields) {
            // only "_method" style names: a plain "method" field in a JSON body is usually business data
            if (typeof field.value === 'string' && /(?:^|[.[])_method\]?$/i.test(field.name) && OVERRIDE_FIELDS.has(fieldLeaf(field.name))) {
                overrides.push({ source: `${field.location}:${clip(field.name, 50)}`, value: field.value });
            }
        }

        const effective = overrides
            .map(override => ({ ...override, value: override.value.trim().toUpperCase().slice(0, 20) }))
            .filter(override => override.value !== '' && override.value !== method);
        if (effective.length === 0) {
            return safe(this.tool);
        }

        const evidence = { method, overrides: effective };
        if (effective.some(override => DANGEROUS.has(override.value))) {
            return violation(this.tool, { ...evidence, reason: 'override_to_dangerous_method' });
        }
        // GET -> DELETE through an override lets a link or <img> perform a state change (CSRF)
        if (!isStateChanging(method) && effective.some(override => isStateChanging(override.value))) {
            return violation(this.tool, { ...evidence, reason: 'safe_method_overridden_to_state_changing' });
        }
        if (new Set(effective.map(override => override.value)).size > 1) {
            return suspicious(this.tool, { ...evidence, reason: 'conflicting_overrides' });
        }
        return suspicious(this.tool, { ...evidence, reason: 'method_overridden' });
    }
}
