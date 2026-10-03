import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface CommandInjectionRule {
    name: string;
    pattern: RegExp;
}

// Commands commonly used in injection payloads (Unix and Windows).
const COMMANDS = [
    'cat', 'ls', 'id', 'whoami', 'uname', 'pwd', 'env', 'printenv', 'ps', 'kill', 'sleep', 'touch', 'tee',
    'rm', 'cp', 'mv', 'chmod', 'chown', 'echo', 'base64', 'ifconfig', 'ip', 'netstat', 'hostname',
    'curl', 'wget', 'nc', 'ncat', 'netcat', 'ping', 'nslookup', 'dig', 'telnet', 'ssh', 'scp',
    'sh', 'bash', 'zsh', 'dash', 'python[23]?', 'perl', 'ruby', 'php', 'node', 'powershell', 'pwsh',
    'cmd', 'dir', 'type', 'ver', 'net', 'tasklist', 'ipconfig', 'systeminfo', 'certutil', 'bitsadmin',
].join('|');

// A command only counts when followed by a flag, path, quote, variable or the end of the
// expression. "; cat people" in prose won't match, "; cat /etc/passwd" or "; ls -la" will.
const COMMAND_WITH_ARGS = `(?:${COMMANDS})\\b(?:\\s+(?:-\\w|[/~.$"'])|\\s*(?:$|[;&|<>)\`]))`;

// No g flag, so RegExp.test has no lastIndex state on these shared constants.
const RULES: CommandInjectionRule[] = [
    {
        // ; cat /etc/passwd   && whoami   | id   || ls -la   newline + command
        name: 'command_chaining',
        pattern: new RegExp(`(?:[;&|\\r\\n]|%0[ad])\\s*${COMMAND_WITH_ARGS}`, 'i'),
    },
    {
        // $(id)   `whoami`
        name: 'command_substitution',
        pattern: new RegExp(`\\$\\(\\s*${COMMAND_WITH_ARGS}|\`\\s*${COMMAND_WITH_ARGS}`, 'i'),
    },
    {
        // cat${IFS}/etc/passwd   (whitespace-filter bypass)
        name: 'ifs_evasion',
        pattern: /\$\{?IFS\}?/,
    },
    {
        name: 'sensitive_path',
        pattern: /\/etc\/(?:passwd|shadow|group|hosts|sudoers)\b|\/proc\/self\b|\/bin\/(?:ba|z|da|k)?sh\b|c:\\windows\\system32/i,
    },
    {
        // cmd /c ...   powershell -enc ...
        name: 'shell_invocation',
        pattern: /\bcmd(?:\.exe)?\s+\/[ck]\b|\bpowershell(?:\.exe)?\s+-/i,
    },
    {
        // /dev/tcp/host/port   bash -i   nc -e   mkfifo
        name: 'reverse_shell',
        pattern: /\/dev\/(?:tcp|udp)\/|\bbash\s+-i\b|\bnc(?:at)?\b[^\r\n]*\s-[a-z]*e\b|\bmkfifo\b/i,
    },
    {
        // > /tmp/x   >> ~/.ssh/authorized_keys   < /etc/passwd
        name: 'redirection_to_path',
        pattern: /[<>]{1,2}\s*(?:\/(?:etc|tmp|dev|var|home|root)\b|~\/)/i,
    },
];

export default class CommandInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'command_injection',
            displayName: 'Command injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SAFE',
                evidence: undefined,
            };
        }

        const value = context.value;
        const matched = RULES
            .filter(rule => rule.pattern.test(value))
            .map(rule => rule.name);

        if (matched.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: matched,
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}