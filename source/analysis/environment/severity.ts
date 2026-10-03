import type { Severity } from './types';

const SEVERITIES: readonly Severity[] = ['unknown', 'info', 'low', 'medium', 'high', 'critical'];

/** Tools disagree on case (Trivy `HIGH`, nuclei `high`) and add values of their own. */
export function normalizeSeverity(raw: string | undefined | null): Severity {
    const value = raw?.trim().toLowerCase();
    return SEVERITIES.find(severity => severity === value) ?? 'unknown';
}
