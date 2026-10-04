export type Severity = 'unknown' | 'info' | 'low' | 'medium' | 'high' | 'critical';

export type EnvironmentTool = 'nmap' | 'nuclei' | 'trivy' | 'httpx' | 'lynis';

export interface SecurityFinding {
    source: EnvironmentTool;
    /** Tool-native rule id: nuclei template id, Trivy AVD/secret rule id, Lynis test id. */
    ruleId: string;
    severity: Severity;
    title: string;
    description: string;
    target?: string;
    /** A location or matched URL only. Never raw bodies, matched secret text or credentials. */
    evidence?: string;
    cves: string[];
    remediation?: string;
}

export interface EnvironmentAnalysisInput {
    tenantId: string;
    /** Absolute path of the project directory; without it Trivy is skipped. */
    projectPath?: string;
    /** http(s) URLs, hostnames or IPs; without any, nmap, httpx and nuclei are skipped. */
    targets: string[];
    /** Tools to skip; each is reported as a skipped run. */
    disabled?: EnvironmentTool[];
    /** Per-tool timeout for this analysis; overrides the analyzer's defaults. */
    timeoutsMs?: Partial<Record<EnvironmentTool, number>>;
    /** Nuclei requests per second (`-rl`); nuclei's own default applies when omitted. */
    nucleiRateLimit?: number;
}

export type ToolFailureKind = 'missing' | 'timeout' | 'exit' | 'parse';

export type ToolRun<T> = (
    | { status: 'ok'; result: T }
    | { status: 'failed'; error: { kind: ToolFailureKind; message: string } }
    | { status: 'skipped'; reason: string }
) & {
    tool: EnvironmentTool;
    startedAt: string;
    durationMs: number;
};

export type NmapPortState =
    | 'open'
    | 'closed'
    | 'filtered'
    | 'unfiltered'
    | 'open|filtered'
    | 'closed|filtered';

export interface NmapPort {
    port: number;
    protocol: 'tcp' | 'udp';
    state: NmapPortState;
    service?: string;
    /** Product and version as reported by service detection, e.g. "nginx 1.24.0". */
    version?: string;
}

export interface NmapHost {
    address: string;
    hostname?: string;
    ports: NmapPort[];
}

export interface NmapResult {
    hosts: NmapHost[];
}

export interface NucleiResult {
    findings: SecurityFinding[];
}

export interface TrivyVulnerability {
    id: string;
    package: string;
    installedVersion: string;
    fixedVersion?: string;
    severity: Severity;
    title: string;
    /** Lockfile or manifest the package was found in. */
    target: string;
}

export interface TrivyResult {
    vulnerabilities: TrivyVulnerability[];
    misconfigurations: SecurityFinding[];
    secrets: SecurityFinding[];
}

export interface HttpTarget {
    url: string;
    statusCode?: number;
    title?: string;
    server?: string;
    technologies: string[];
    /** Response headers without cookies or credentials. */
    headers?: Record<string, string>;
    tls?: {
        enabled: boolean;
        version?: string;
    };
}

export interface HttpxResult {
    targets: HttpTarget[];
}

export interface LynisResult {
    score?: number;
    /** False when not run as root: Lynis then performs only a partial audit. */
    privileged: boolean;
    warnings: SecurityFinding[];
    suggestions: SecurityFinding[];
}

export interface EnvironmentAnalysisResult {
    tenantId: string;
    startedAt: string;
    completedAt: string;
    nmap: ToolRun<NmapResult>;
    nuclei: ToolRun<NucleiResult>;
    trivy: ToolRun<TrivyResult>;
    httpx: ToolRun<HttpxResult>;
    lynis: ToolRun<LynisResult>;
}
