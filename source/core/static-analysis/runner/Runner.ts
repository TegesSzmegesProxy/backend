import { NormalizedRequest } from '@tessera/shared/contracts';
import { ContextMap, Tool, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export type ToolStep =
    | { tool: Tool<ToolContextType.Field>; target: string }
    | { tool: Tool<ToolContextType.File>; target: string }
    | { tool: Tool<ToolContextType.Full> };

export type ExecutionPlan = ToolStep[];

export class Runner {
    run(request: NormalizedRequest, plan: ExecutionPlan): ToolResult[] {
        const results: ToolResult[] = [];

        for (const step of plan) {
            for (const context of this.resolveContexts(request, step)) {
                results.push(this.execute(step.tool, context));
            }
        }

        return results;
    }

    private resolveContexts(request: NormalizedRequest, step: ToolStep): ContextMap[ToolContextType][] {
        switch (step.tool.metadata.contextType) {
            case ToolContextType.Field:
                return request.fields.filter((field) => field.name === (step as { target: string }).target);
            case ToolContextType.File:
                return request.files.filter((file) => file.field === (step as { target: string }).target);
            case ToolContextType.Full:
                return [request];
        }
    }

    private execute(tool: Tool<ToolContextType>, context: ContextMap[ToolContextType]): ToolResult {
        try {
            return tool.run(context as never);
        } catch (error) {
            return {
                tool: tool.tool,
                status: 'ERROR',
                verdict: 'ERROR',
                evidence: error instanceof Error ? error.message : String(error),
            };
        }
    }
}
