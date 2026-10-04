import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface SstiRule {
    name: string;
    pattern: RegExp;
}

// A plain {{name}} placeholder is common in user content (and harmless), so expression rules require
// arithmetic, a call, an attribute walk or a filter inside the delimiters.
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: SstiRule[] = [
    {
        // {{7*7}}  {{ 7 * '7' }}  {{config.items()}}  {{ x|attr("__class__") }}
        name: 'curly_expression',
        pattern: /\{\{[^{}]{0,200}?(?:\d\s*[-+*/%]\s*['"]?\d|\(\s*\)|\|\s*(?:attr|safe|e|join|format|map|select)\b|\.__\w+__|\[\s*['"]__)[^{}]{0,200}\}\}/i,
    },
    {
        // {{ config }}  {{ self }}  {{ request.application }}  {{ settings.SECRET_KEY }}
        name: 'template_globals',
        pattern: /\{\{\s*(?:config|self|request\.(?:application|environ)|settings\.\w+|_self|app\.request)\b[^}]{0,100}\}\}/i,
    },
    {
        // __class__.__mro__[1].__subclasses__()  lipsum.__globals__  cycler.__init__.__globals__.os
        name: 'python_sandbox_escape',
        pattern: /__(?:class|mro|subclasses|globals|builtins|init|base|bases|import)__|\b(?:lipsum|cycler|joiner|namespace)\s*\.\s*__/i,
    },
    {
        // {% import os %}  {% for x in ().__class__ %}  {% set x = ... %}
        name: 'statement_block',
        pattern: /\{%-?\s*(?:import|include|extends|set|for|if|macro|call|filter|raw|debug)\b[^%]{0,200}%\}/i,
    },
    {
        // ${7*7}  #{7*7}  *{7*7}  @(7*7)  -- EL, Ruby, Thymeleaf, Razor arithmetic probes
        name: 'arithmetic_probe',
        pattern: /[$#*@]\{\s*\d+\s*[-+*/%]\s*\d+\s*\}|@\(\s*\d+\s*[-+*/%]\s*\d+\s*\)/,
    },
    {
        // <%= 7*7 %>  <%= system("id") %>  (ERB, EJS)
        name: 'erb_tag',
        pattern: /<%[=-]?\s*[^%]{0,200}(?:\d\s*[-+*/]\s*\d|\w+\s*\(|`)[^%]{0,200}%>/,
    },
    {
        // <#assign ex="freemarker.template.utility.Execute"?new()>  ${"freemarker.template...
        name: 'freemarker_gadget',
        pattern: /<#(?:assign|include|import|list|attempt)\b|freemarker\.template\.utility\.(?:Execute|ObjectConstructor|JythonRuntime)|\?new\s*\(\s*\)|\?api\b/i,
    },
    {
        // {{_self.env.registerUndefinedFilterCallback("exec")}}  {{['id']|filter('system')}}
        name: 'twig_gadget',
        pattern: /registerUndefinedFilterCallback|getFilter\s*\(|\|\s*(?:filter|map|reduce|sort)\s*\(\s*['"](?:system|exec|passthru|shell_exec|popen)['"]/i,
    },
    {
        // #set($x = ...)  $class.inspect("java.lang.Runtime")  #foreach  (Velocity)
        name: 'velocity_directive',
        pattern: /#set\s*\(\s*\$\w+\s*=|\$class\.(?:inspect|type)\s*\(|#foreach\s*\(\s*\$/i,
    },
    {
        // {php}...{/php}  {system('id')}  {Smarty_Internal_Write_File::writeFile(...)}
        name: 'smarty_tag',
        pattern: /\{\/?php\}|\{\s*(?:system|exec|passthru|shell_exec)\s*\(|Smarty_Internal_\w+/i,
    },
    {
        // {{#with "s" as |string|}}  {{constructor.constructor('return process')()}}  (Handlebars / Angular)
        name: 'handlebars_or_angular_gadget',
        pattern: /\{\{\s*#with\s+["'][^"']*["']\s+as\s+\|\w+\|\s*\}\}|constructor\s*\.\s*constructor\s*\(|\{\{\s*\$on\.constructor/i,
    },
];

export default class Ssti extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'ssti',
            displayName: 'Server-side template injection (SSTI)',
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
