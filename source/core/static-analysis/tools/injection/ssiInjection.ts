import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, decodeLayers, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface SsiRule {
    name: string;
    pattern: RegExp;
}

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: SsiRule[] = [
    {
        // <!--#exec cmd="id" -->   <!--#exec cgi="/cgi-bin/x" -->
        name: 'ssi_exec',
        pattern: /<!--\s*#\s*exec\b/i,
    },
    {
        // <!--#include virtual="/etc/passwd" -->  <!--#echo var="DOCUMENT_ROOT" -->  <!--#printenv -->
        name: 'ssi_directive',
        pattern: /<!--\s*#\s*(?:include|echo|config|set|printenv|fsize|flastmod|if|elif|else|endif)\b/i,
    },
    {
        // <esi:include src="http://evil/"/>  <esi:vars>$(HTTP_COOKIE)</esi:vars>   (Edge Side Includes on CDNs)
        name: 'esi_tag',
        pattern: /<\s*esi\s*:\s*(?:include|vars|inline|choose|when|eval|debug|assign|try|attempt|remove)\b/i,
    },
];

export default class SsiInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'ssi_injection',
            displayName: 'Server-side include injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        // also catches %3C!--%23exec cmd=...
        const layers = decodeLayers(context.value.slice(0, 16_384), 2);
        const matched = RULES.filter(rule => layers.some(layer => rule.pattern.test(layer))).map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched })
            : safe(this.tool);
    }
}
