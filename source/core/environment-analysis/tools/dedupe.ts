/** Keeps the first item for each key. Scanners repeat a finding once per matcher, template or probe. */
export function uniqueBy<T>(items: T[], key: (item: T) => unknown[]): T[] {
    const seen = new Set<string>();
    return items.filter(item => {
        const id = JSON.stringify(key(item));
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    });
}

export const findingKey = (f: { ruleId: string; target?: string | undefined; evidence?: string | undefined }) => [
    f.ruleId,
    f.target,
    f.evidence,
];
