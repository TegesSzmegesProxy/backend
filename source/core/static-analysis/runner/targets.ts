import type { RequestField, RequestFile } from '@tessera/shared/contracts';

type FieldMatcher = (field: Pick<RequestField, 'location' | 'name'>) => boolean;

// Targets come from verified bundles, so this cache holds a bounded set.
const matchers = new Map<string, FieldMatcher>();

/**
 * Field targets name `location.name`. `*` matches every field, `body.*` / `query.*` every field of a location, and
 * `[]` any array index, so the policy's `items[].sku` matches the normalizer's `items.0.sku`.
 */
export function matchesFieldTarget(target: string, field: Pick<RequestField, 'location' | 'name'>): boolean {
    let matcher = matchers.get(target);
    if (!matcher) {
        matcher = compile(target);
        matchers.set(target, matcher);
    }
    return matcher(field);
}

export function matchesFileTarget(target: string, file: Pick<RequestFile, 'field'>): boolean {
    return target === '*' || file.field === target;
}

function compile(target: string): FieldMatcher {
    if (target === '*') return () => true;
    if (target === 'body.*' || target === 'query.*') {
        const location = target.slice(0, -2);
        return (field) => field.location === location;
    }
    if (!target.includes('[]')) return (field) => `${field.location}.${field.name}` === target;
    const pattern = new RegExp(`^${target.split('[]').map(escape).join('\\.\\d+')}$`);
    return (field) => pattern.test(`${field.location}.${field.name}`);
}

function escape(value: string): string {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
