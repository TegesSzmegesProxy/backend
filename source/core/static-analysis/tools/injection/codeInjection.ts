import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface CodeInjectionRule {
    name: string;
    pattern: RegExp;
}

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: CodeInjectionRule[] = [
    {
        // eval("...")  eval(atob(...))  setTimeout("code")  new Function("return process")()
        name: 'js_dynamic_evaluation',
        pattern: /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|\bset(?:Timeout|Interval|Immediate)\s*\(\s*['"`]/,
    },
    {
        // require('child_process').exec(...)  process.mainModule.require  global.process  process.binding
        name: 'node_process_access',
        pattern: /require\s*\(\s*['"`](?:child_process|fs|vm|net|os|worker_threads)['"`]\s*\)|\bprocess\s*\.\s*(?:mainModule|binding|dlopen|kill|exit)\b|\bchild_process\s*\.\s*(?:exec|spawn|fork|execSync|spawnSync)\b|\bglobal(?:This)?\s*\.\s*process\b/,
    },
    {
        // this.constructor.constructor("return process")()   [].constructor.constructor
        name: 'constructor_escape',
        pattern: /\.constructor\s*\.\s*constructor\s*\(|\.constructor\s*\[\s*['"`]constructor['"`]\s*\]/,
    },
    {
        // system("id")  passthru(  shell_exec(  assert($_GET[..])  create_function(  call_user_func(
        name: 'php_code_execution',
        pattern: /\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|assert|create_function|call_user_func(?:_array)?|include|require(?:_once)?)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|['"`]|\$\w+\s*\))/i,
    },
    {
        // preg_replace('/.*/e', ...)   -- the /e modifier evaluates the replacement as PHP
        name: 'php_preg_replace_eval',
        pattern: /preg_replace\s*\(\s*['"]([^\w\s\\]).*?\1[imsxuADSUXJ]*e[imsxuADSUXJ]*['"]/,
    },
    {
        // <?php ... ?>  <?= ... ?>
        name: 'php_open_tag',
        pattern: /<\?(?:php\b|=)/i,
    },
    {
        // __import__('os').system(  os.system(  subprocess.Popen(  exec(compile(  getattr(__builtins__
        name: 'python_code_execution',
        pattern: /__import__\s*\(\s*['"](?:os|subprocess|sys|pty|socket)['"]\s*\)|\b(?:os\s*\.\s*(?:system|popen|exec\w*|spawn\w*)|subprocess\s*\.\s*(?:Popen|call|run|check_output))\s*\(|\bexec\s*\(\s*compile\s*\(|getattr\s*\(\s*__builtins__/,
    },
    {
        // Kernel.exec  `id` in Ruby  instance_eval  Runtime.getRuntime  (generic reflective execution)
        name: 'ruby_or_jvm_execution',
        pattern: /\b(?:Kernel\s*\.\s*(?:exec|system|spawn)|instance_eval|class_eval|module_eval|IO\s*\.\s*popen)\b|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/,
    },
];

export default class CodeInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'code_injection',
            displayName: 'Code injection',
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
