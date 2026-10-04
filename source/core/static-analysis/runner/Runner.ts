import { NormalizedRequest } from '@tessera/shared/contracts';
import { ContextMap, Tool, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';
import { matchesFieldTarget, matchesFileTarget } from './targets';

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
                    .then(result => ('target' in step ? { ...result, target: this.targetOf(step, context) } : result)));
            }
        }

        return Promise.all(pending);
    }

    // A wildcard or array-item target reports the concrete field or upload it ran on.
    private targetOf(step: ToolStep & { target: string }, context: ContextMap[ToolContextType]): string {
        switch (step.tool.metadata.contextType) {
            case ToolContextType.Field: {
                const field = context as ContextMap[ToolContextType.Field];
                return `${field.location}.${field.name}`;
            }
            case ToolContextType.File:
                return (context as ContextMap[ToolContextType.File]).field;
            default:
                return step.target;
        }
    }

    private resolveContexts(request: NormalizedRequest, step: ToolStep): ContextMap[ToolContextType][] {
        switch (step.tool.metadata.contextType) {
            case ToolContextType.Field:
                return request.fields.filter((field) => matchesFieldTarget((step as { target: string }).target, field));
            case ToolContextType.File:
                return request.files.filter((file) => matchesFileTarget((step as { target: string }).target, file));
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
