import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, safe, violation } from '@tessera/core/static-analysis/shared';
import Xxe from '../injection/xxe';

// <!ENTITY name "value">, internal entities only; external ones are the XXE tool's concern.
// matchAll clones the regex, so the g flag is safe on this shared constant.
const ENTITY = /<!ENTITY\s+(?!%)([\w.-]+)\s+(["'])([\s\S]*?)\2\s*>/gi;
const REFERENCE = /&([\w.-]+);/g;

export default class XmlBomb extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'xml_bomb'>) {
        super({
            id: 'xml_bomb',
            displayName: 'XML bomb',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        for (const { source, text } of Xxe.xmlSources(context)) {
            if (!/<!ENTITY/i.test(text)) continue;
            const finding = this.analyze(text);
            if (finding) {
                return violation(this.tool, { source, ...finding });
            }
        }
        return safe(this.tool);
    }

    // Computes how large each entity expands to (bottom-up, cycles count as infinite) and how much the
    // document body references them. Sizes are estimated without expanding anything.
    private analyze(text: string): Record<string, unknown> | undefined {
        const { maxEntities, maxExpandedBytes, maxNesting } = this.config;
        const definitions = new Map<string, string>();
        for (const match of text.matchAll(ENTITY)) {
            definitions.set(match[1], match[3]);
        }
        if (definitions.size === 0) {
            return undefined;
        }

        const sizes = new Map<string, number>();
        const depths = new Map<string, number>();
        const visiting = new Set<string>();
        const expand = (name: string): { size: number; depth: number } => {
            if (sizes.has(name)) return { size: sizes.get(name)!, depth: depths.get(name)! };
            const value = definitions.get(name);
            if (value === undefined) return { size: name.length + 2, depth: 0 }; // predefined (&amp;) or undeclared
            if (visiting.has(name)) return { size: Infinity, depth: Infinity }; // recursive entity
            visiting.add(name);
            let size = value.replace(REFERENCE, '').length;
            let depth = 0;
            for (const ref of value.matchAll(REFERENCE)) {
                const inner = expand(ref[1]);
                size += inner.size;
                depth = Math.max(depth, inner.depth + 1);
                if (size > maxExpandedBytes * 1000) break;
            }
            visiting.delete(name);
            sizes.set(name, size);
            depths.set(name, depth);
            return { size, depth };
        };

        let largest = 0;
        let nesting = 0;
        for (const name of definitions.keys()) {
            const { size, depth } = expand(name);
            largest = Math.max(largest, size);
            nesting = Math.max(nesting, depth);
        }

        // quadratic blowup: one large entity referenced many times in the body, no nesting needed
        const body = text.replace(/<!DOCTYPE[\s\S]*?\]\s*>/i, '');
        let bodyExpansion = 0;
        for (const ref of body.matchAll(REFERENCE)) {
            bodyExpansion += sizes.get(ref[1]) ?? 0;
            if (bodyExpansion > maxExpandedBytes) break;
        }

        const reasons: string[] = [];
        if (!Number.isFinite(largest)) reasons.push('recursive_entity');
        if (definitions.size > maxEntities) reasons.push('too_many_entities');
        if (nesting > maxNesting) reasons.push('nested_entity_expansion'); // billion laughs
        if (largest > maxExpandedBytes || bodyExpansion > maxExpandedBytes) reasons.push('expansion_too_large');

        return reasons.length > 0
            ? {
                reasons,
                entities: definitions.size,
                nesting: Number.isFinite(nesting) ? nesting : 'recursive',
                estimatedBytes: Number.isFinite(largest) ? Math.max(largest, bodyExpansion) : 'unbounded',
            }
            : undefined;
    }
}
