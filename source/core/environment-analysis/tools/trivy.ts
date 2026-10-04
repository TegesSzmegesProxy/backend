import { z } from 'zod';
import { findingKey, uniqueBy } from './dedupe';
import { normalizeSeverity } from '../severity';
import type { SecurityFinding, TrivyResult, TrivyVulnerability } from '../types';

const locationFields = { StartLine: z.number().optional(), EndLine: z.number().optional() };

const resultSchema = z.object({
    Target: z.string(),
    Vulnerabilities: z
        .array(
            z.object({
                VulnerabilityID: z.string(),
                PkgName: z.string(),
                InstalledVersion: z.string(),
                FixedVersion: z.string().optional(),
                Severity: z.string().optional(),
                Title: z.string().optional(),
            })
        )
        .nullish(),
    Misconfigurations: z
        .array(
            z.object({
                ID: z.string(),
                AVDID: z.string().nullish(),
                Title: z.string(),
                Description: z.string().optional(),
                Resolution: z.string().optional(),
                Severity: z.string().optional(),
                Status: z.string().optional(),
                CauseMetadata: z.object(locationFields).nullish(),
            })
        )
        .nullish(),
    Secrets: z
        .array(
            z.object({
                RuleID: z.string(),
                Category: z.string().optional(),
                Title: z.string(),
                Severity: z.string().optional(),
                ...locationFields,
            })
        )
        .nullish(),
});

const reportSchema = z.object({ Results: z.array(resultSchema).nullish() });

export const trivyArgs = (projectPath: string): string[] => [
    'fs',
    '--format',
    'json',
    '--scanners',
    'vuln,misconfig,secret',
    '--quiet',
    projectPath,
];

export function parseTrivy(output: string): TrivyResult {
    const results = reportSchema.parse(JSON.parse(output) as unknown).Results ?? [];
    const parsed: TrivyResult = { vulnerabilities: [], misconfigurations: [], secrets: [] };

    for (const result of results) {
        for (const vuln of result.Vulnerabilities ?? []) {
            parsed.vulnerabilities.push(toVulnerability(result.Target, vuln));
        }
        for (const misconfig of result.Misconfigurations ?? []) {
            if (misconfig.Status !== undefined && misconfig.Status !== 'FAIL') continue;
            parsed.misconfigurations.push({
                source: 'trivy',
                ruleId: misconfig.AVDID ?? misconfig.ID,
                severity: normalizeSeverity(misconfig.Severity),
                title: misconfig.Title,
                description: misconfig.Description ?? '',
                target: result.Target,
                evidence: location(result.Target, misconfig.CauseMetadata ?? {}),
                cves: [],
                ...(misconfig.Resolution !== undefined && { remediation: misconfig.Resolution }),
            });
        }
        for (const secret of result.Secrets ?? []) {
            // Trivy also returns `Match` and `Code`; they contain the secret and are never read.
            parsed.secrets.push({
                source: 'trivy',
                ruleId: secret.RuleID,
                severity: normalizeSeverity(secret.Severity),
                title: secret.Title,
                description: `${secret.Category ?? 'Credential'} secret found in ${result.Target}`,
                target: result.Target,
                evidence: location(result.Target, secret),
                cves: [],
                remediation: 'Remove the secret from the repository and rotate it.',
            });
        }
    }
    return {
        vulnerabilities: uniqueBy(parsed.vulnerabilities, v => [v.id, v.package, v.installedVersion, v.target]),
        misconfigurations: uniqueBy(parsed.misconfigurations, findingKey),
        secrets: uniqueBy(parsed.secrets, findingKey),
    };
}

function toVulnerability(
    target: string,
    vuln: NonNullable<z.infer<typeof resultSchema>['Vulnerabilities']>[number]
): TrivyVulnerability {
    return {
        id: vuln.VulnerabilityID,
        package: vuln.PkgName,
        installedVersion: vuln.InstalledVersion,
        ...(vuln.FixedVersion !== undefined && { fixedVersion: vuln.FixedVersion }),
        severity: normalizeSeverity(vuln.Severity),
        title: vuln.Title ?? vuln.VulnerabilityID,
        target,
    };
}

function location(target: string, { StartLine, EndLine }: { StartLine?: number | undefined; EndLine?: number | undefined }): string {
    if (StartLine === undefined) return target;
    return EndLine !== undefined && EndLine !== StartLine ? `${target}:${StartLine}-${EndLine}` : `${target}:${StartLine}`;
}
