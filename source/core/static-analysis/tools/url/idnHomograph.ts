import { domainToUnicode } from 'node:url';
import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious, urlAuthorities } from '@tessera/core/static-analysis/shared';

// Characters that render (almost) like a Latin letter or digit. A small subset of Unicode's confusables.txt.
const CONFUSABLES: Record<string, string> = {
    // Cyrillic
    'а': 'a', 'в': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'ё': 'e', 'һ': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k',
    'ӏ': 'l', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'ѕ': 's', 'т': 't', 'у': 'y', 'х': 'x', 'ԝ': 'w', 'ь': 'b',
    // Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    // Latin look-alikes and digits
    'ɑ': 'a', 'ɡ': 'g', 'ı': 'i', 'ł': 'l', 'ŀ': 'l', 'ɩ': 'i', 'ʏ': 'y', 'ᴠ': 'v', 'ꮃ': 'w', '0': 'o', '1': 'l',
};

const SCRIPTS: [string, RegExp][] = [
    ['latin', /\p{Script=Latin}/u],
    ['cyrillic', /\p{Script=Cyrillic}/u],
    ['greek', /\p{Script=Greek}/u],
    ['armenian', /\p{Script=Armenian}/u],
    ['cherokee', /\p{Script=Cherokee}/u],
];

export default class IdnHomograph extends Tool<ToolContextType.Field> {
    constructor(private readonly config: ToolConfig<'idn_homograph'>) {
        super({
            id: 'idn_homograph',
            displayName: 'IDN homograph',
            category: ToolCategory.Url,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = context.value.slice(0, 4096);
        const hosts = urlAuthorities(value).map(authority => authority.host);
        const email = value.trim().match(/^[^@\s]+@([^@\s]+)$/);
        if (email) hosts.push(email[1].toLowerCase());
        if (hosts.length === 0 && /^[^\s/:@]+\.[^\s/:@]+$/.test(value.trim())) hosts.push(value.trim().toLowerCase());

        const findings: { host: string; unicode?: string; rules: string[]; imitates?: string }[] = [];
        for (const host of hosts) {
            const unicode = host.includes('xn--') ? domainToUnicode(host) || host : host;
            const rules: string[] = [];

            if (host.split('.').some(label => label.startsWith('xn--'))) rules.push('punycode_label');
            const mixed = unicode.split('.').some(label => SCRIPTS.filter(([, script]) => script.test(label)).length > 1);
            if (mixed) rules.push('mixed_script_label');

            const skeleton = IdnHomograph.skeleton(unicode);
            const imitates = this.config.protectedDomains.find(domain =>
                (skeleton === domain || skeleton.endsWith(`.${domain}`)) && unicode !== domain && !unicode.endsWith(`.${domain}`),
            );
            if (imitates) rules.push('confusable_with_protected_domain');

            // punycode alone is a legitimate internationalized domain; it only matters combined with another sign
            if (rules.length > 1 || imitates || mixed) {
                findings.push({ host: clip(host, 100), unicode: unicode !== host ? clip(unicode, 100) : undefined, rules, imitates });
            }
        }

        return findings.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, findings: findings.slice(0, 5) })
            : safe(this.tool);
    }

    // Maps every confusable character to the letter it imitates, so "раураl.com" becomes "paypal.com".
    private static skeleton(host: string): string {
        return [...host.normalize('NFKC').toLowerCase()]
            .map(char => CONFUSABLES[char] ?? char)
            .join('')
            .replace(/rn/g, 'm')
            .replace(/vv/g, 'w');
    }
}
