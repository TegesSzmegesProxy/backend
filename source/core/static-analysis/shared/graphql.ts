import { NormalizedRequest } from '@tessera/shared/contracts';

// A small, forgiving GraphQL scanner shared by the GraphQL tools. It does not validate documents; it only
// measures them (depth, aliases, cost, fragments, directives), so malformed input still yields numbers.

export interface GraphqlDocument {
    query: string;
    variables: unknown;
}

export interface GraphqlStats {
    depth: number;
    fields: number;
    aliases: number;
    /** Fields weighted by the list sizes (first/last/limit/take) of their ancestors. */
    cost: number;
    directives: number;
    maxDirectivesPerField: number;
    /** Field name -> how many times it was requested under an alias (alias batching). */
    aliasedFields: Map<string, number>;
    /** Field name -> how many times it appears. */
    fieldCounts: Map<string, number>;
    fragments: number;
    fragmentCycle: boolean;
    operations: number;
    /** Introspection meta fields used (__schema, __type); __typename is harmless and not listed. */
    introspection: string[];
}

const MAX_TOKENS = 50_000;
const PAGE_ARGUMENTS = new Set(['first', 'last', 'limit', 'take', 'pagesize', 'perpage', 'count']);

/** The GraphQL documents a request carries: a JSON body, a batched array body, or ?query= on GET. */
export function graphqlDocuments(request: NormalizedRequest): GraphqlDocument[] {
    const fromObject = (value: unknown): GraphqlDocument | undefined => {
        if (typeof value === 'object' && value !== null && typeof (value as Record<string, unknown>)['query'] === 'string') {
            const record = value as Record<string, unknown>;
            return { query: record['query'] as string, variables: record['variables'] };
        }
        return undefined;
    };

    if (Array.isArray(request.body)) {
        return request.body.map(fromObject).filter((doc): doc is GraphqlDocument => doc !== undefined);
    }
    const single = fromObject(request.body);
    if (single) {
        return [single];
    }
    const query = request.query?.['query'];
    if (typeof query === 'string' && query.trim() !== '') {
        let variables: unknown;
        try {
            variables = request.query['variables'] ? JSON.parse(request.query['variables']) : undefined;
        } catch {
            variables = request.query['variables'];
        }
        return [{ query, variables }];
    }
    return [];
}

type Token = { kind: 'name' | 'punct' | 'number' | 'string'; text: string };

function tokenize(source: string): Token[] {
    const tokens: Token[] = [];
    let index = 0;
    while (index < source.length && tokens.length < MAX_TOKENS) {
        const char = source[index];
        if (/[\s,﻿]/.test(char)) {
            index++;
        } else if (char === '#') {
            while (index < source.length && source[index] !== '\n') index++;
        } else if (source.startsWith('"""', index)) {
            const end = source.indexOf('"""', index + 3);
            index = end === -1 ? source.length : end + 3;
            tokens.push({ kind: 'string', text: '' });
        } else if (char === '"') {
            index++;
            while (index < source.length && source[index] !== '"' && source[index] !== '\n') {
                index += source[index] === '\\' ? 2 : 1;
            }
            index++;
            tokens.push({ kind: 'string', text: '' });
        } else if (source.startsWith('...', index)) {
            tokens.push({ kind: 'punct', text: '...' });
            index += 3;
        } else if (/[_A-Za-z]/.test(char)) {
            const match = /^[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(index, index + 256))!;
            tokens.push({ kind: 'name', text: match[0] });
            index += match[0].length;
        } else if (/[-0-9]/.test(char)) {
            const match = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index, index + 64));
            tokens.push({ kind: 'number', text: match ? match[0] : char });
            index += match ? match[0].length : 1;
        } else {
            tokens.push({ kind: 'punct', text: char });
            index++;
        }
    }
    return tokens;
}

interface FragmentInfo {
    depth: number;
    spreads: { name: string; depth: number }[];
}

export function analyzeGraphql(source: string): GraphqlStats {
    const tokens = tokenize(source);
    const stats: GraphqlStats = {
        depth: 0, fields: 0, aliases: 0, cost: 0, directives: 0, maxDirectivesPerField: 0,
        aliasedFields: new Map(), fieldCounts: new Map(), fragments: 0, fragmentCycle: false, operations: 0, introspection: [],
    };

    const fragments = new Map<string, FragmentInfo>();
    const operationSpreads: { name: string; depth: number }[] = [];
    let currentFragment: FragmentInfo | undefined;

    let braceDepth = 0;
    let parenDepth = 0;
    // multiplier per open selection set; the field that opened it set `pendingMultiplier`
    const multipliers: number[] = [1];
    let pendingMultiplier = 1;
    let directivesOnField = 0;

    for (let index = 0; index < tokens.length; index++) {
        const token = tokens[index];
        const next = tokens[index + 1];

        if (token.kind === 'punct') {
            if (token.text === '{') {
                if (braceDepth === 0 && !currentFragment) stats.operations++;
                braceDepth++;
                multipliers.push(multipliers[multipliers.length - 1] * pendingMultiplier);
                pendingMultiplier = 1;
                const lexical = braceDepth - 1;
                if (currentFragment) currentFragment.depth = Math.max(currentFragment.depth, lexical);
                else stats.depth = Math.max(stats.depth, lexical);
            } else if (token.text === '}') {
                braceDepth = Math.max(0, braceDepth - 1);
                multipliers.pop();
                if (braceDepth === 0) currentFragment = undefined;
            } else if (token.text === '(') {
                parenDepth++;
            } else if (token.text === ')') {
                parenDepth = Math.max(0, parenDepth - 1);
            } else if (token.text === '@' && next?.kind === 'name') {
                stats.directives++;
                directivesOnField++;
                stats.maxDirectivesPerField = Math.max(stats.maxDirectivesPerField, directivesOnField);
                index++; // skip the directive name
            } else if (token.text === '...' && next?.kind === 'name' && next.text !== 'on') {
                const spread = { name: next.text, depth: braceDepth - 1 };
                (currentFragment ? currentFragment.spreads : operationSpreads).push(spread);
                index++;
            }
            continue;
        }

        if (token.kind !== 'name') continue;

        // fragment Name on Type { ... }
        if (braceDepth === 0 && token.text === 'fragment' && next?.kind === 'name') {
            currentFragment = { depth: 0, spreads: [] };
            fragments.set(next.text, currentFragment);
            stats.fragments++;
            index++;
            continue;
        }
        if (braceDepth === 0 || parenDepth > 0) {
            // operation keywords, names, variable definitions and arguments
            if (parenDepth > 0 && PAGE_ARGUMENTS.has(token.text.toLowerCase()) && tokens[index + 1]?.text === ':' && tokens[index + 2]?.kind === 'number') {
                pendingMultiplier = Math.max(pendingMultiplier, Math.min(Number(tokens[index + 2].text) || 1, 10_000));
            }
            continue;
        }
        if (tokens[index - 1]?.text === 'on' || token.text === 'on' && tokens[index - 1]?.text === '...') {
            continue; // type condition of an inline fragment
        }

        // alias: name ':' name
        let fieldName = token.text;
        if (next?.text === ':' && tokens[index + 2]?.kind === 'name') {
            fieldName = tokens[index + 2].text;
            stats.aliases++;
            stats.aliasedFields.set(fieldName, (stats.aliasedFields.get(fieldName) ?? 0) + 1);
            index += 2;
        }

        stats.fields++;
        directivesOnField = 0;
        pendingMultiplier = 1;
        stats.fieldCounts.set(fieldName, (stats.fieldCounts.get(fieldName) ?? 0) + 1);
        stats.cost += multipliers[multipliers.length - 1];
        if ((fieldName === '__schema' || fieldName === '__type') && !stats.introspection.includes(fieldName)) {
            stats.introspection.push(fieldName);
        }
    }

    // Expand fragment spreads for depth, and detect cycles (a fragment that spreads itself, directly or not).
    const resolved = new Map<string, number>();
    const visiting = new Set<string>();
    const fragmentDepth = (name: string): number => {
        if (resolved.has(name)) return resolved.get(name)!;
        const fragment = fragments.get(name);
        if (!fragment) return 0;
        if (visiting.has(name)) {
            stats.fragmentCycle = true;
            return 0;
        }
        visiting.add(name);
        let depth = fragment.depth;
        for (const spread of fragment.spreads) {
            depth = Math.max(depth, spread.depth + fragmentDepth(spread.name));
        }
        visiting.delete(name);
        resolved.set(name, depth);
        return depth;
    };
    for (const name of fragments.keys()) {
        fragmentDepth(name);
    }
    for (const spread of operationSpreads) {
        stats.depth = Math.max(stats.depth, spread.depth + fragmentDepth(spread.name));
    }

    return stats;
}
