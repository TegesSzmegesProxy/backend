import { z } from 'zod';
import { normalizeSeverity } from '../severity';
import type { NucleiResult, SecurityFinding } from '../types';
import { findingKey, uniqueBy } from './dedupe';
import { jsonLines } from './httpx';

// `cve-id` is an array, a single string or an explicit null depending on the template.
const lineSchema = z.object({
    'template-id': z.string(),
    info: z.object({
        name: z.string(),
        severity: z.string().optional(),
        description: z.string().optional(),
        remediation: z.string().optional(),
        classification: z
            .object({ 'cve-id': z.union([z.array(z.string()), z.string(), z.null()]).optional() })
            .nullish(),
    }),
    host: z.string().optional(),
    'matched-at': z.string().optional(),
});

export const nucleiArgs = (urls: string[], rateLimit?: number): string[] => [
    ...urls.flatMap(url => ['-u', url]),
    '-jsonl',
    '-silent',
    '-no-color',
    '-disable-update-check',
    // Scope the scan: templates for the detected stack only, no low-signal or risky ones, bounded requests.
    '-automatic-scan',
    '-severity',
    'medium,high,critical',
    '-exclude-tags',
    'dos,intrusive,fuzz',
    '-timeout',
    '5',
    '-concurrency',
    '25',
    ...(rateLimit !== undefined ? ['-rl', String(rateLimit)] : []),
];

export function parseNuclei(output: string): NucleiResult {
    // `request`, `response` and `extracted-results` are deliberately never read:
    // they can hold credentials and are not needed to explain a finding.
    const findings = jsonLines(output).map(line => toFinding(lineSchema.parse(line)));
    return { findings: uniqueBy(findings, findingKey) };
}

function toFinding(line: z.infer<typeof lineSchema>): SecurityFinding {
    const raw = line.info.classification?.['cve-id'];
    const cves = (Array.isArray(raw) ? raw : raw ? [raw] : []).map(id => id.toUpperCase());
    return {
        source: 'nuclei',
        ruleId: line['template-id'],
        severity: normalizeSeverity(line.info.severity),
        title: line.info.name,
        description: (line.info.description ?? '').trim(),
        ...(line.host !== undefined && { target: line.host }),
        ...(line['matched-at'] !== undefined && { evidence: line['matched-at'] }),
        cves,
        ...(line.info.remediation !== undefined && { remediation: line.info.remediation.trim() }),
    };
}
