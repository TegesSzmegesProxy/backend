import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, header, safe, suspicious, violation } from '@tessera/core/static-analysis/shared';

// User agents security scanners send by default.
const SCANNER_USER_AGENTS: { tool: string; pattern: RegExp }[] = [
    { tool: 'sqlmap', pattern: /sqlmap/i },
    { tool: 'nikto', pattern: /nikto/i },
    { tool: 'nuclei', pattern: /nuclei|projectdiscovery/i },
    { tool: 'burp', pattern: /burp(?:suite|collaborator)?/i },
    { tool: 'ffuf', pattern: /\bffuf\b|Fuzz Faster U Fool/i },
    { tool: 'gobuster', pattern: /gobuster/i },
    { tool: 'feroxbuster', pattern: /feroxbuster/i },
    { tool: 'dirbuster', pattern: /dirbuster|\bdirb\b/i },
    { tool: 'wfuzz', pattern: /wfuzz/i },
    { tool: 'nmap', pattern: /nmap scripting engine|\bnmap\b/i },
    { tool: 'masscan', pattern: /masscan/i },
    { tool: 'zgrab', pattern: /zgrab/i },
    { tool: 'acunetix', pattern: /acunetix|wvs/i },
    { tool: 'netsparker', pattern: /netsparker|invicti/i },
    { tool: 'owasp_zap', pattern: /\bZAP\/|OWASP[ _]ZAP/i },
    { tool: 'w3af', pattern: /w3af/i },
    { tool: 'arachni', pattern: /arachni/i },
    { tool: 'openvas', pattern: /openvas|greenbone/i },
    { tool: 'wpscan', pattern: /wpscan/i },
    { tool: 'whatweb', pattern: /whatweb/i },
    { tool: 'hydra', pattern: /\bhydra\b/i },
    { tool: 'jaeles', pattern: /jaeles/i },
    { tool: 'commix', pattern: /commix/i },
];

// Headers some scanners add to every request.
const SCANNER_HEADERS = ['x-scanner', 'acunetix-product', 'acunetix-scanning-agreement', 'acunetix-user-agreement', 'x-wvs-id', 'x-nuclei-template'];

// Out-of-band callback domains used by scanners to confirm blind injections.
const OAST_DOMAINS = /\b[\w-]+\.(?:oast\.(?:pro|live|site|online|fun|me)|interact\.sh|interactsh\.com|burpcollaborator\.net|oastify\.com|dnslog\.cn|ceye\.io|requestbin\.net|canarytokens\.com|pipedream\.net|webhook\.site)\b/i;

export default class ScannerSignature extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'scanner_signature',
            displayName: 'Scanner signature',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const userAgent = header(context, 'user-agent') ?? '';
        const tools = SCANNER_USER_AGENTS.filter(entry => entry.pattern.test(userAgent)).map(entry => entry.tool);
        const headers = SCANNER_HEADERS.filter(name => header(context, name) !== undefined);

        // a scanner announcing itself: nothing legitimate runs sqlmap against production
        if (tools.length > 0 || headers.length > 0) {
            return violation(this.tool, { tools, headers, userAgent: clip(userAgent, 150) });
        }

        // a callback domain in a payload: probably a scanner, but could be a researcher's honest test
        const sources: string[] = [];
        for (const field of context.fields) {
            if (typeof field.value === 'string' && OAST_DOMAINS.test(field.value)) sources.push(`${field.location}:${clip(field.name, 50)}`);
        }
        for (const [name, value] of Object.entries(context.headers ?? {})) {
            if (OAST_DOMAINS.test(String(value))) sources.push(`header:${clip(name, 50)}`);
        }

        return sources.length > 0 ? suspicious(this.tool, { rule: 'out_of_band_callback_domain', sources: sources.slice(0, 10) }) : safe(this.tool);
    }
}
