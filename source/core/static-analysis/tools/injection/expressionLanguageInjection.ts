import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface ElRule {
    name: string;
    pattern: RegExp;
}

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: ElRule[] = [
    {
        // T(java.lang.Runtime).getRuntime().exec('id')   T( java.lang.System )   (SpEL type reference)
        name: 'spel_type_reference',
        pattern: /\bT\s*\(\s*(?:java|javax|org\.springframework|sun|com\.sun)\.[\w.$]+\s*\)/,
    },
    {
        // new java.lang.ProcessBuilder(...)   new javax.script.ScriptEngineManager()
        name: 'constructor_call',
        pattern: /\bnew\s+(?:java\.lang\.(?:ProcessBuilder|Runtime|Thread)|javax\.script\.ScriptEngineManager|java\.net\.URLClassLoader|java\.io\.File\w*)\b/,
    },
    {
        // @java.lang.Runtime@getRuntime()   @org.apache.commons.io.IOUtils@toString   (OGNL static access)
        name: 'ognl_static_access',
        pattern: /@(?:java|javax|org|com|sun)\.[\w.$]+@\w+/,
    },
    {
        // #_memberAccess   #context['xwork.MethodAccessor.denyMethodExecution']   %{#...}   (Struts2 OGNL)
        name: 'ognl_context',
        pattern: /#_memberAccess|#context\s*\[|%\{\s*#|#(?:request|session|application|attr|parameters)\s*\[\s*['"]struts|ognl\.OgnlContext|DEFAULT_MEMBER_ACCESS|#ct\s*=/,
    },
    {
        // Runtime.getRuntime().exec(   .getClass().forName(   .getClassLoader()
        name: 'reflection_chain',
        pattern: /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b|\.\s*getClass\s*\(\s*\)\s*\.\s*(?:forName|getClassLoader|getMethod|getDeclaredMethod)\b|\bClass\s*\.\s*forName\s*\(/,
    },
    {
        // ${...} / #{...} wrapping a method call or class access  (JSP EL, SpEL templates, MVEL)
        name: 'el_method_invocation',
        pattern: /[$#]\{[^}]{0,200}(?:\.\s*(?:getClass|exec|invoke|newInstance|forName|getRuntime|getProperty|getenv)\s*\(|java\.lang\.)[^}]{0,200}\}/,
    },
    {
        // ${applicationScope}  ${pageContext.request}  ${header}  ${initParam}  (JSP implicit objects)
        name: 'el_implicit_object',
        pattern: /\$\{\s*(?:applicationScope|sessionScope|requestScope|pageContext|initParam|header|cookie|param)\b/,
    },
];

export default class ExpressionLanguageInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'expression_language_injection',
            displayName: 'Expression language injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = context.value;
        const matched = RULES.filter(rule => rule.pattern.test(value)).map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched })
            : safe(this.tool);
    }
}
