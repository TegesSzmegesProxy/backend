import type { LynisResult, SecurityFinding } from '../types';

export const lynisArgs = (reportFile: string): string[] => [
    'audit',
    'system',
    '--quick',
    '--no-colors',
    '--no-log',
    '--report-file',
    reportFile,
];

/** Parses the `key=value` report file Lynis writes. `-` marks an empty field. */
export function parseLynis(report: string, privileged: boolean): LynisResult {
    const lines = report.split('\n');
    if (!lines.some(line => line.startsWith('lynis_version='))) {
        throw new Error('not a Lynis report');
    }

    const score = lines.find(line => line.startsWith('hardening_index='))?.split('=')[1];
    return {
        ...(score !== undefined && Number.isFinite(Number(score)) && { score: Number(score) }),
        privileged,
        warnings: findings(lines, 'warning[]=', 'medium'),
        suggestions: findings(lines, 'suggestion[]=', 'low'),
    };
}

function findings(lines: string[], prefix: string, severity: SecurityFinding['severity']): SecurityFinding[] {
    return lines
        .filter(line => line.startsWith(prefix))
        .map(line => {
            const [ruleId = '', text = '', details = '-', solution = '-'] = line.slice(prefix.length).split('|');
            return {
                source: 'lynis' as const,
                ruleId,
                severity,
                title: text,
                description: text,
                ...(details !== '-' && details !== '' && { target: details }),
                cves: [],
                ...(solution !== '-' && solution !== '' && { remediation: solution }),
            };
        });
}
