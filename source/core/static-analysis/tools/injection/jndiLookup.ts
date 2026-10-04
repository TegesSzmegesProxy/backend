import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, decodeLayers, safe, suspicious } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 8192;
const MAX_RESOLVE_ROUNDS = 10;

// Log4j lookups that only ever return (part of) their own argument, which is how payloads are obfuscated:
// ${lower:J}, ${upper:n}, ${::-d}, ${env:NOPE:-i}, ${date:'j'}, ${base64:...} is not resolvable and stays.
const INNER_LOOKUP = /\$\{(?:(?:lower|upper)\s*:\s*([^${}]*)|(?:[^${}:]*:)*?[^${}:]*:-([^${}]*)|date\s*:\s*'([^'${}]*)')\}/gi;

const JNDI = /\$\{\s*jndi\s*:\s*(ldaps?|rmi|dns|iiop|corba|nds|nis|http|https)?\s*:?/i;

export default class JndiLookup extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'jndi_lookup',
            displayName: 'JNDI lookup (Log4Shell)',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || !/\$|%24/i.test(context.value)) {
            return safe(this.tool);
        }

        const rules = new Set<string>();
        let protocol: string | undefined;

        for (const layer of decodeLayers(context.value.slice(0, MAX_LENGTH))) {
            const resolved = JndiLookup.resolve(layer);
            const match = JNDI.exec(resolved);
            if (match) {
                rules.add(resolved === layer ? 'jndi_lookup' : 'obfuscated_jndi_lookup');
                protocol = protocol ?? match[1]?.toLowerCase();
            }
            // nested lookups that resolve to plain characters exist only to dodge filters
            if (resolved !== layer && /\$\{/.test(layer)) {
                rules.add('nested_lookup_obfuscation');
            }
            if (/\$\{\s*(?:env|sys|java|main|bundle|ctx|spring|k8s|docker|log4j)\s*:/i.test(layer)) {
                rules.add('information_lookup'); // ${env:AWS_SECRET_ACCESS_KEY}, exfiltrated via DNS
            }
        }

        if (rules.size === 0) {
            return safe(this.tool);
        }
        return suspicious(this.tool, { name: clip(context.name), location: context.location, rules: [...rules], protocol });
    }

    // Replaces self-resolving inner lookups with their result until nothing changes.
    private static resolve(value: string): string {
        let current = value;
        for (let round = 0; round < MAX_RESOLVE_ROUNDS; round++) {
            const next = current.replace(INNER_LOOKUP, (_, caseArg?: string, fallback?: string, date?: string) =>
                caseArg ?? fallback ?? date ?? '',
            );
            if (next === current) break;
            current = next;
        }
        return current;
    }
}
