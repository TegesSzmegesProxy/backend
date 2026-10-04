import { ToolResult } from './Tool';

// Result builders, so every tool reports the four verdicts the same way.

export function safe(tool: string): ToolResult {
    return { tool, status: 'SUCCESS', verdict: 'SAFE', evidence: undefined };
}

/** The tool found something it cannot be fully confident about; JEV decides. */
export function suspicious(tool: string, evidence: unknown): ToolResult {
    return { tool, status: 'SUCCESS', verdict: 'SUSPICIOUS', evidence };
}

/** The tool is confident the request breaks a policy and should be rejected. */
export function violation(tool: string, evidence: unknown): ToolResult {
    return { tool, status: 'SUCCESS', verdict: 'POLICY_VIOLATION', evidence };
}

/** The tool could not evaluate the request, which is different from "safe". */
export function failure(tool: string, evidence: unknown): ToolResult {
    return { tool, status: 'ERROR', verdict: 'ERROR', evidence };
}
