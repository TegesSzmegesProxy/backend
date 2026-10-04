import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, decodeLayers, pathOf, safe, violation } from '@tessera/core/static-analysis/shared';

interface ProbeRule {
    name: string;
    pattern: RegExp;
}

// Files and paths that only exist on someone else's stack or that no deployment should serve.
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: ProbeRule[] = [
    { name: 'environment_file', pattern: /\/\.env(?:\.[\w-]+)?$|\/\.env\b/i },
    { name: 'version_control', pattern: /\/\.(?:git|svn|hg|bzr)(?:\/|$)|\/\.gitignore$|\/\.git-credentials$/i },
    { name: 'os_metadata', pattern: /\/\.DS_Store$|\/Thumbs\.db$|\/desktop\.ini$/i },
    { name: 'wordpress_probe', pattern: /\/(?:wp-login\.php|wp-admin(?:\/|$)|xmlrpc\.php|wp-config\.php|wp-content\/(?:plugins|debug\.log))/i },
    { name: 'php_info', pattern: /\/(?:php)?info\.php$|\/phpinfo(?:\.php)?$|\/test\.php$/i },
    { name: 'server_status', pattern: /\/server-(?:status|info)$|\/nginx_status$/i },
    { name: 'backup_file', pattern: /\.(?:bak|backup|old|orig|save|swp|swo|tmp|~)$|~$|\/(?:backup|dump|db|database|site|www)\.(?:zip|tar|tar\.gz|tgz|rar|7z|sql|sql\.gz)$/i },
    { name: 'database_dump', pattern: /\.(?:sql|sqlite|sqlite3|db|mdb)(?:\.gz)?$/i },
    { name: 'credentials_file', pattern: /\/(?:\.htpasswd|\.htaccess|web\.config|\.npmrc|\.pypirc|\.netrc|\.dockercfg|id_rsa|id_ed25519|\.aws\/credentials|\.ssh\/|credentials\.json|secrets\.ya?ml)/i },
    { name: 'ide_or_config', pattern: /\/\.(?:vscode|idea)\/|\/(?:config|configuration|settings)\.(?:php|inc|ya?ml|json|ini)(?:\.bak)?$|\/docker-compose\.ya?ml$|\/\.dockerenv$/i },
    { name: 'admin_tooling', pattern: /\/(?:phpmyadmin|pma|adminer(?:\.php)?|myadmin|manager\/html|solr\/admin|jmx-console|web-console)(?:\/|$)/i },
    { name: 'debug_endpoint', pattern: /\/(?:actuator\/(?:env|heapdump|threaddump|configprops|mappings)|_profiler|telescope|elmah\.axd|trace\.axd|debug\/(?:pprof|vars))(?:\/|$)/i },
];

export default class SensitiveFileProbe extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'sensitive_file_probe',
            displayName: 'Sensitive file probe',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const raw = pathOf(context).split('?')[0];
        // "/%2eenv" and "/.git%2fconfig" are the same probe
        const layers = decodeLayers(raw, 2).map(layer => layer.replace(/\\/g, '/').replace(/\/{2,}/g, '/'));
        const matched = RULES.filter(rule => layers.some(layer => rule.pattern.test(layer))).map(rule => rule.name);

        // a request for these has no legitimate purpose against this application
        return matched.length > 0 ? violation(this.tool, { rules: matched, path: clip(raw, 200) }) : safe(this.tool);
    }
}
