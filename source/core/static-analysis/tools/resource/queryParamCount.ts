import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, header, safe, violation } from '@tessera/core/static-analysis/shared';

export default class QueryParamCount extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'query_param_count'>) {
        super({
            id: 'query_param_count',
            displayName: 'Query and form parameter count',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // fields, not context.query: the normalizer keeps every repeated value ("a=1&a=2" -> a.0, a.1)
        const queryParams = context.fields.filter(field => field.location === 'query').length;

        const contentType = (header(context, 'content-type') ?? '').toLowerCase();
        const isForm = contentType.startsWith('application/x-www-form-urlencoded') || contentType.startsWith('multipart/form-data');
        const formParams = isForm ? context.fields.filter(field => field.location === 'body').length : 0;

        const { maxQueryParams, maxFormParams } = this.config;
        const reasons: string[] = [];
        if (queryParams > maxQueryParams) reasons.push('too_many_query_parameters');
        if (formParams > maxFormParams) reasons.push('too_many_form_parameters');

        return reasons.length > 0
            ? violation(this.tool, { reasons, queryParams, formParams, maxQueryParams, maxFormParams })
            : safe(this.tool);
    }
}
