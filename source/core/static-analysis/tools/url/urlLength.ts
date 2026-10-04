import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, pathOf, safe, violation } from '@tessera/core/static-analysis/shared';

export default class UrlLength extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'url_length'>) {
        super({
            id: 'url_length',
            displayName: 'URL length',
            category: ToolCategory.Url,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const path = pathOf(context).split('?')[0];
        // the normalizer drops the raw query string, so its length is rebuilt from the parsed parameters
        const queryLength = context.fields
            .filter(field => field.location === 'query')
            .reduce((sum, field) => sum + encodeURIComponent(field.name).length + encodeURIComponent(String(field.value ?? '')).length + 2, 0);
        const longestSegment = Math.max(0, ...path.split('/').map(segment => segment.length));

        const { maxPathLength, maxSegmentLength, maxQueryLength, maxUrlLength } = this.config;
        const reasons: string[] = [];
        if (path.length > maxPathLength) reasons.push('path_too_long');
        if (longestSegment > maxSegmentLength) reasons.push('segment_too_long');
        if (queryLength > maxQueryLength) reasons.push('query_too_long');
        if (path.length + queryLength > maxUrlLength) reasons.push('url_too_long');

        return reasons.length > 0
            ? violation(this.tool, { reasons, pathLength: path.length, longestSegment, queryLength })
            : safe(this.tool);
    }
}
