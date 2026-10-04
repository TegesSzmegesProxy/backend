import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface DeserializationRule {
    name: string;
    pattern: RegExp;
}

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: DeserializationRule[] = [
    {
        // AC ED 00 05 stream header: hex, or base64 "rO0AB", or gzip+base64 "H4sIAAAAAAAA" wrapping it
        name: 'java_serialized',
        pattern: /\baced0005|(?:^|[^A-Za-z0-9+/])rO0AB[A-Za-z0-9+/=]{4,}|\\xac\\xed\\x00\\x05/i,
    },
    {
        // ysoserial gadget class names
        name: 'java_gadget_class',
        pattern: /org\.apache\.commons\.collections\d*\.(?:functors|keyvalue)|com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl|org\.springframework\.beans\.factory\.ObjectFactory|java\.beans\.XMLDecoder|com\.sun\.rowset\.JdbcRowSetImpl|org\.codehaus\.groovy\.runtime\.ConvertedClosure/,
    },
    {
        // "@type":"com.sun.rowset.JdbcRowSetImpl"   (fastjson / Jackson polymorphic typing)
        name: 'json_type_hint',
        pattern: /["'](?:@type|@class|\$type|java\.lang\.Class)["']\s*:\s*["'][\w.$]+\.[\w.$]+/,
    },
    {
        // O:8:"stdClass":1:{...}   a:2:{i:0;O:...}   C:11:"ArrayObject"   (PHP serialize)
        name: 'php_serialized_object',
        pattern: /(?:^|[;{])\s*[OC]:\d+:"[\w\\]+":\d+:\{|^a:\d+:\{(?:[is]:\d+[:;].*?)?[OC]:\d+:"/,
    },
    {
        // pickle protocol 2-5 opcodes: \x80\x04\x95 raw or "gASV" base64; "cos\nsystem" (protocol 0); __reduce__
        name: 'python_pickle',
        pattern: /\\x80\\x0[2-5]|(?:^|[^A-Za-z0-9+/])gA[SJRE]V[A-Za-z0-9+/=]{4,}|\bc(?:os|posix|subprocess|builtins|__builtin__)\n(?:system|popen|exec|eval|check_output)\b|__reduce(?:_ex)?__/,
    },
    {
        // AAEAAAD/////  is the BinaryFormatter header in base64; ObjectStateFormatter / LosFormatter ViewState gadgets
        name: 'dotnet_binaryformatter',
        pattern: /AAEAAAD\/\/\/\/\/|System\.Windows\.Data\.ObjectDataProvider|System\.Diagnostics\.Process\b|TypeConfuseDelegate|System\.Configuration\.Install\.AssemblyInstaller/,
    },
    {
        // !!python/object/apply:os.system   !!javax.script.ScriptEngineManager   !ruby/object:Gem::Installer
        name: 'yaml_tag',
        pattern: /!!python\/(?:object|name|module|apply)|!!(?:javax|java|com|org)\.[\w.]+|!ruby\/(?:object|hash|struct):/,
    },
    {
        // \x04\x08 Marshal header ("BAh" in base64), and node-serialize's IIFE marker
        name: 'ruby_or_node_serialized',
        pattern: /(?:^|[^A-Za-z0-9+/])BAh[A-Za-z0-9+/]{2}[A-Za-z0-9+/=]{4,}|_\$\$ND_FUNC\$\$_/,
    },
];

export default class InsecureDeserialization extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'insecure_deserialization',
            displayName: 'Insecure deserialization',
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
