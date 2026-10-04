import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export default class RequestSize extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'request_size'>) {
        super({
            id: 'request_size',
            displayName: 'Request size',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const { maxBytes } = this.config;

        let jsonBytes: number;
        try {
            // query, headers and body are the raw inputs; `fields` is derived from them, so it's not counted again
            jsonBytes = Buffer.byteLength(
                JSON.stringify({ query: context.query, headers: context.headers, body: context.body }),
                'utf8',
            );
        } catch (error) {
            // circular references, BigInt values, or a throwing toJSON()
            return {
                tool: this.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: error instanceof Error ? error.message : String(error),
            };
        }

        const fileBytes = context.files.reduce(
            (total, file) => total + (Number.isFinite(file.size) && file.size > 0 ? file.size : 0),
            0,
        );
        const bytes = jsonBytes + fileBytes;

        if (bytes > maxBytes) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                evidence: { bytes, maxBytes, jsonBytes, fileBytes },
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