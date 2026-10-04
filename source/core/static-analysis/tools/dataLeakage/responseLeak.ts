import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, header, metadataOf, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

interface LeakRule {
    name: string;
    pattern: RegExp;
    /** Internal addresses can appear for honest reasons; stack traces and SQL errors can't. */
    certain: boolean;
}

const MAX_SCAN = 512 * 1024;

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: LeakRule[] = [
    { name: 'java_stack_trace', pattern: /\bat [\w$.]+\([\w$]+\.java:\d+\)|Exception in thread "|^\s*Caused by: [\w.]+(?:Exception|Error)/m, certain: true },
    { name: 'node_stack_trace', pattern: /^\s+at (?:[\w$.<>\s[\]]+ \()?(?:\/|[A-Z]:\\|node:)[^)\n]+:\d+:\d+\)?$/m, certain: true },
    { name: 'python_traceback', pattern: /Traceback \(most recent call last\):|File "[^"]+", line \d+, in /, certain: true },
    { name: 'dotnet_error', pattern: /Server Error in '\/[^']*' Application|System\.\w+Exception:|at [\w.]+\(\) in [A-Z]:\\/, certain: true },
    { name: 'php_error', pattern: /<b>(?:Fatal error|Warning|Parse error|Notice)<\/b>:|(?:Fatal error|Parse error): .+ in \/.+ on line \d+/, certain: true },
    { name: 'ruby_or_go_trace', pattern: /\.rb:\d+:in `|goroutine \d+ \[running\]:|panic: runtime error/, certain: true },
    {
        name: 'sql_error',
        pattern: /You have an error in your SQL syntax|\bORA-\d{5}\b|PG::\w+Error|SQLSTATE\[\w+\]|sqlite3?\.OperationalError|Unclosed quotation mark after the character string|org\.postgresql\.util\.PSQLException|com\.mysql\.jdbc|MongoServerError|E11000 duplicate key error/,
        certain: true,
    },
    { name: 'debug_page', pattern: /Werkzeug Debugger|DEBUG = True|Whoops! There was an error|Ignition\\|<title>Django .*Error|Laravel.*(?:Exception|stack trace)|phpinfo\(\)|<title>Error \d+ - Tomcat/i, certain: true },
    { name: 'environment_dump', pattern: /\b(?:AWS_SECRET_ACCESS_KEY|DATABASE_URL|SECRET_KEY_BASE|DB_PASSWORD|JWT_SECRET)\s*[=:]/, certain: true },
    { name: 'internal_ip', pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/, certain: false },
    { name: 'filesystem_path', pattern: /(?:\/(?:home|var\/www|usr\/src\/app|opt|srv)\/[\w.-]+\/[\w./-]+\.\w{1,5}|[A-Z]:\\(?:inetpub|Users|Program Files)\\[^\s"'<]+)/, certain: false },
];

// Response headers that only debug builds send.
const DEBUG_HEADERS = ['x-debug-token', 'x-debug-token-link', 'x-aspnet-version', 'x-powered-by', 'x-sourcemap', 'sourcemap'];

export default class ResponseLeak extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'response_leak',
            displayName: 'Response leak',
            category: ToolCategory.DataLeakage,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        // only meaningful on the response pass; before the upstream answers there is nothing to inspect
        const response = metadataOf(context).response;
        if (!response) {
            return safe(this.tool);
        }

        const body = typeof response.body === 'string' ? response.body.slice(0, MAX_SCAN) : '';
        const matched = RULES.filter(rule => rule.pattern.test(body));

        const responseHeaders = Object.fromEntries(Object.entries(response.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
        const debugHeaders = DEBUG_HEADERS.filter(name => responseHeaders[name] !== undefined && (name !== 'x-powered-by' || /\d/.test(String(responseHeaders[name]))));

        if (matched.length === 0 && debugHeaders.length === 0) {
            return safe(this.tool);
        }

        const evidence = {
            status: response.status,
            endpoint: context.endpoint,
            leaks: matched.map(rule => rule.name),
            debugHeaders,
            // the request that triggered the error is often the probe itself
            requestContentType: header(context, 'content-type'),
        };
        return matched.some(rule => rule.certain) ? violation(this.tool, evidence) : suspicious(this.tool, evidence);
    }
}
