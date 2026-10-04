import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface LdapRule {
    name: string;
    pattern: RegExp;
}

// Meant for identity fields (username, uid, cn, mail) that end up inside an LDAP search filter.
// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: LdapRule[] = [
    {
        // admin)(|(uid=*   *)(uid=*))(|(uid=*   x)(!(&(1=0   -- closing the filter and opening a new clause
        name: 'filter_breakout',
        pattern: /\)\s*\(\s*[|&!]|\*\s*\)\s*\(|\)\s*\(\s*[\w-]+\s*[~<>]?=/,
    },
    {
        // (|(uid=x)(uid=y))  (&(objectClass=*)...)
        name: 'boolean_clause',
        pattern: /\(\s*[|&!]\s*\(/,
    },
    {
        // uid=*   objectClass=*   cn=adm*   -- attribute presence or wildcard assertions inside the value
        name: 'attribute_assertion',
        pattern: /\b(?:uid|cn|sn|mail|objectclass|userpassword|samaccountname|memberof|ou|dc|givenname|description)\s*[~<>]?=\s*[*(]/i,
    },
    {
        // a value that is only a wildcard: matches every entry
        name: 'wildcard_only',
        pattern: /^\s*\*+\s*$/,
    },
    {
        // \2a \28 \29 \00 escapes smuggled in, or a raw NUL truncating the filter
        name: 'escaped_metacharacter',
        pattern: /\\(?:2a|28|29|5c|00)|\u0000|%00/i,
    },
];

export default class LdapInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'ldap_injection',
            displayName: 'LDAP injection',
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
