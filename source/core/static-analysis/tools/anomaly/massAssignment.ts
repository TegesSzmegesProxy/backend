import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, isStateChanging, methodOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

export default class MassAssignment extends Tool<ToolContextType.Full> {
    // properties a user should never set on their own records, compared after lowercasing and removing "_" and "-"
    private readonly privileged: ReadonlySet<string>;

    constructor(config: ToolConfig<'mass_assignment'>) {
        super({
            id: 'mass_assignment',
            displayName: 'Mass assignment',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
        this.privileged = new Set(config.privilegedFields);
    }

    override run(context: NormalizedRequest): ToolResult {
        if (!isStateChanging(methodOf(context))) {
            return safe(this.tool);
        }

        // any path segment counts: {"user": {"role": "admin"}} arrives as "user.role"
        const matched = context.fields
            .filter(field => field.location === 'body' || field.location === 'query')
            .filter(field => field.name.split(/[[\].]+/).some(segment => this.privileged.has(segment.toLowerCase().replace(/[_-]/g, ''))))
            .map(field => ({ field: clip(field.name), location: field.location }));

        if (matched.length > 0) {
            // suspicious, not a violation: admin APIs legitimately set these, and the tool can't see who is calling
            return suspicious(this.tool, { fields: matched.slice(0, 10) });
        }
        return safe(this.tool);
    }
}
