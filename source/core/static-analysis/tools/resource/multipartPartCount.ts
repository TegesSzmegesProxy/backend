import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, header, metadataOf, safe, violation } from '@tessera/core/static-analysis/shared';

export default class MultipartPartCount extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'multipart_part_count'>) {
        super({
            id: 'multipart_part_count',
            displayName: 'Multipart part count',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const contentType = header(context, 'content-type') ?? '';
        if (!/^\s*multipart\//i.test(contentType)) {
            return safe(this.tool);
        }

        const reasons: string[] = [];
        const boundaries = [...contentType.matchAll(/;\s*boundary\s*=\s*(?:"([^"]*)"|([^;\s]*))/gi)].map(match => match[1] ?? match[2] ?? '');
        const boundary = boundaries[0];

        if (boundary === undefined || boundary === '') reasons.push('missing_boundary');
        else if (boundary.length > this.config.maxBoundaryLength) reasons.push('boundary_too_long');
        else if (!/^[0-9A-Za-z'()+_,\-./:=? ]*[0-9A-Za-z'()+_,\-./:=?]$/.test(boundary)) reasons.push('invalid_boundary_characters');
        // two boundary parameters: parsers disagree on which one wins
        if (boundaries.length > 1) reasons.push('duplicate_boundary_parameter');

        // part count from the parser when available, otherwise files plus body fields
        const reported = metadataOf(context).multipart?.parts;
        const parts = typeof reported === 'number' ? reported : context.files.length + context.fields.filter(field => field.location === 'body').length;
        if (parts > this.config.maxParts) reasons.push('too_many_parts');
        if (context.files.length > this.config.maxFiles) reasons.push('too_many_files');

        return reasons.length > 0
            ? violation(this.tool, { reasons, parts, files: context.files.length, boundaryLength: boundary?.length ?? 0 })
            : safe(this.tool);
    }
}
