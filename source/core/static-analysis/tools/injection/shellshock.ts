import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

// "() { :; };", "() { :;};", "() { _; } >_[$($())] { ...": a bash function definition at the start of a value
// that CGI turns into an environment variable (CVE-2014-6271 and its variants).
// No g flag, so RegExp.test has no lastIndex state on this shared constant.
const FUNCTION_DEFINITION = /\(\s*\)\s*\{[^}]{0,50}\}\s*[;>]|\(\s*\)\s*\{\s*(?::|_)\s*;/;

export default class Shellshock extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'shellshock',
            displayName: 'Shellshock',
            category: ToolCategory.Injection,
            // Full context: headers are the classic carrier (User-Agent, Referer, Cookie), and CGI exports
            // query and form values to the environment too
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const sources: string[] = [];

        for (const [name, value] of Object.entries(context.headers ?? {})) {
            if (FUNCTION_DEFINITION.test(String(value))) sources.push(`header:${clip(name, 50)}`);
        }
        for (const field of context.fields) {
            if (typeof field.value === 'string' && FUNCTION_DEFINITION.test(field.value)) {
                sources.push(`${field.location}:${clip(field.name, 50)}`);
            }
        }

        return sources.length > 0 ? suspicious(this.tool, { sources: sources.slice(0, 10) }) : safe(this.tool);
    }
}
