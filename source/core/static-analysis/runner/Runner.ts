import { NormalizedRequest } from '@tessera/shared/contracts';
import { ContextMap, Tool, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

export type ToolStep =
    | { tool: Tool<ToolContextType.Field>; target: string }
    | { tool: Tool<ToolContextType.File>; target: string }
    | { tool: Tool<ToolContextType.Full> };

export type ExecutionPlan = ToolStep[];

export class Runner {
    /** Runs every step concurrently; results keep plan order. */
    async run(request: NormalizedRequest, plan: ExecutionPlan): Promise<ToolResult[]> {
        const pending: Promise<ToolResult>[] = [];

        for (const step of plan) {
            for (const context of this.resolveContexts(request, step)) {
                pending.push(this.execute(step.tool, context)
                    .then(result => ('target' in step ? { ...result, target: step.target } : result)));
            }
        }

        return Promise.all(pending);
    }

    private resolveContexts(request: NormalizedRequest, step: ToolStep): ContextMap[ToolContextType][] {
        switch (step.tool.metadata.contextType) {
            case ToolContextType.Field:
                return request.fields.filter((field) => `${field.location}.${field.name}` === (step as { target: string }).target);
            case ToolContextType.File:
                return request.files.filter((file) => file.field === (step as { target: string }).target);
            case ToolContextType.Full:
                return [request];
        }
    }

    // A throw or a rejected promise (e.g. Redis unavailable for a stateful tool) is an ERROR, never SAFE.
    private async execute(tool: Tool<ToolContextType>, context: ContextMap[ToolContextType]): Promise<ToolResult> {
        try {
            return await tool.run(context as never);
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
