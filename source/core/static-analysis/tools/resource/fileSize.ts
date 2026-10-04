import { RequestFile, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class FileSize extends Tool<ToolContextType.File> {
    constructor(private readonly config: ToolConfig<'file_size'>) {
        super({
            id: 'file_size',
            displayName: 'File size',
            category: ToolCategory.Resource,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        const { maxBytes } = this.config;

        // A size we can't trust means we can't evaluate the file, which is different from "safe"
        if (typeof context.size !== 'number' || !Number.isFinite(context.size) || context.size < 0) {
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: { filename: context.filename, size: String(context.size).slice(0, 50), reason: 'invalid_size' },
            };
        }

        if (context.size > maxBytes) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: { filename: context.filename, size: context.size, maxBytes },
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}