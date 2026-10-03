import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseHttpx } from '../../../source/analysis/environment/tools/httpx';
import { parseLynis } from '../../../source/analysis/environment/tools/lynis';
import { parseNmap } from '../../../source/analysis/environment/tools/nmap';
import { parseNuclei } from '../../../source/analysis/environment/tools/nuclei';
import { parseTrivy } from '../../../source/analysis/environment/tools/trivy';

const fixture = (name: string) => readFileSync(join(__dirname, 'fixtures', name), 'utf8');

describe('parseNmap', () => {
    it('reads hosts, ports, states and service versions', () => {
        const { hosts } = parseNmap(fixture('nmap.xml'));
        expect(hosts).toHaveLength(1);
        expect(hosts[0]).toMatchObject({ address: '127.0.0.1', hostname: 'localhost' });
        expect(hosts[0]?.ports).toEqual([
            { port: 22, protocol: 'tcp', state: 'closed', service: 'ssh' },
            { port: 8099, protocol: 'tcp', state: 'open', service: 'http', version: 'SimpleHTTPServer 0.6' },
        ]);
    });

    it('rejects output that is not nmap XML', () => {
        expect(() => parseNmap('not xml')).toThrow();
    });
});

describe('parseHttpx', () => {
    it('reads the fingerprint and drops cookie headers', () => {
        const { targets } = parseHttpx(fixture('httpx.jsonl'));
        expect(targets).toHaveLength(1);
        expect(targets[0]).toMatchObject({
            url: 'http://127.0.0.1:8099',
            statusCode: 200,
            server: 'SimpleHTTP/0.6 Python/3.12.3',
            technologies: ['Python:3.12.3', 'SimpleHTTP:0.6'],
            tls: { enabled: true, version: 'tls13' },
        });
        expect(targets[0]?.headers).toHaveProperty('content-type', 'text/html');
        expect(Object.keys(targets[0]?.headers ?? {})).not.toContain('set-cookie');
    });

    it('skips probes that failed to connect', () => {
        const failed = JSON.stringify({ url: 'http://nowhere', failed: true });
        expect(parseHttpx(failed).targets).toEqual([]);
    });
});

describe('parseNuclei', () => {
    it('tags findings with the tool and normalizes CVE ids', () => {
        const { findings } = parseNuclei(fixture('nuclei.jsonl'));
        expect(findings).toHaveLength(2);
        expect(findings[0]).toMatchObject({ source: 'nuclei', ruleId: 'http-missing-security-headers', severity: 'info', cves: [] });
        expect(findings[1]).toMatchObject({
            ruleId: 'CVE-2021-41773',
            severity: 'critical',
            cves: ['CVE-2021-41773'],
            remediation: 'Upgrade Apache',
        });
    });

    it('never carries the request or response', () => {
        expect(fixture('nuclei.jsonl')).toContain('"response"');
        expect(JSON.stringify(parseNuclei(fixture('nuclei.jsonl')))).not.toContain('HTTP/1.0 200');
    });
});

describe('parseTrivy', () => {
    const result = parseTrivy(fixture('trivy.json'));

    it('reads vulnerabilities with their lockfile and normalized severity', () => {
        expect(result.vulnerabilities).toContainEqual(
            expect.objectContaining({
                id: 'CVE-2020-8203',
                package: 'lodash',
                installedVersion: '4.17.15',
                fixedVersion: '4.17.19',
                severity: 'high',
                target: 'package-lock.json',
            })
        );
    });

    it('reads misconfigurations, falling back to ID when AVDID is null', () => {
        expect(result.misconfigurations).toContainEqual(
            expect.objectContaining({ source: 'trivy', ruleId: 'DS-0002', severity: 'high', evidence: 'Dockerfile:2' })
        );
    });

    it('reports secrets by location only', () => {
        expect(fixture('trivy.json')).toContain('"Match"');
        expect(result.secrets).toEqual([
            expect.objectContaining({ ruleId: 'github-pat', severity: 'critical', evidence: '.env:1' }),
        ]);
        expect(JSON.stringify(result.secrets)).not.toContain('GITHUB_TOKEN');
    });

    it('accepts a clean report without Results', () => {
        expect(parseTrivy('{"SchemaVersion":2}')).toEqual({ vulnerabilities: [], misconfigurations: [], secrets: [] });
    });
});

describe('parseLynis', () => {
    it('maps the hardening index, warnings and suggestions', () => {
        const result = parseLynis(fixture('lynis.dat'), false);
        expect(result.score).toBe(65);
        expect(result.privileged).toBe(false);
        expect(result.warnings).toHaveLength(2);
        expect(result.warnings[0]).toMatchObject({ source: 'lynis', ruleId: 'MAIL-8818', severity: 'medium' });
        expect(result.warnings[1]).toMatchObject({ target: '/etc/postgresql/16/main/postgresql.conf', remediation: 'Use chmod 600 to change file permissions' });
        expect(result.suggestions).toHaveLength(3);
        expect(result.suggestions[0]).toMatchObject({ severity: 'low' });
    });

    it('rejects text that is not a Lynis report', () => {
        expect(() => parseLynis('hello', true)).toThrow();
    });
});
