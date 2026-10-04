import { randomUUID } from "node:crypto";
import type { Decision } from "../../core/decisionOrchestrator/orchestrator";
import type { BundleManager } from "../../core/policy/BundleManager";
import { BUNDLE_SCHEMA, HEARTBEAT_SCHEMA, SUPPORTED_TOOL_REGISTRIES, TELEMETRY_SCHEMA } from "../contracts/bundle";
import { heartbeatSchema, telemetryBatchSchema } from "../contracts/operations";

interface EndpointCounters {
  endpoint: string | null;
  decisions: { allow: number; block: number };
  staticVerdicts: { safe: number; suspicious: number; policyViolation: number; error: number };
  jev: { sampledSafe: number; attack: number; benign: number; unavailable: number };
  failureBehaviorApplied: number;
}

const empty = (endpoint: string | null): EndpointCounters => ({
  endpoint,
  decisions: { allow: 0, block: 0 },
  staticVerdicts: { safe: 0, suspicious: 0, policyViolation: 0, error: 0 },
  jev: { sampledSafe: 0, attack: 0, benign: 0, unavailable: 0 },
  failureBehaviorApplied: 0,
});

/** Best-effort, redacted minute counters. No request content enters this module. */
export class ProxyReporter {
  readonly instanceId = randomUUID();
  private readonly windows = new Map<number, Map<string, EndpointCounters>>();
  private lastEvents = { pullFailures: 0, verificationFailures: 0 };
  private droppedWindows = 0;
  private timer?: NodeJS.Timeout;
  private sending = false;
  private pending?: { body: unknown; minutes: number[]; pullFailures: number; verificationFailures: number; droppedWindows: number };

  constructor(
    private readonly options: { tenantId: string; apiBaseUrl: string; deploymentKey: string; proxyVersion: string },
    private readonly bundles: BundleManager,
  ) {}

  record(endpoint: string | null, decision: Decision | { action: "ALLOW" | "BLOCK" }, failureBehaviorApplied = false): void {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    let window = this.windows.get(minute);
    if (!window) { window = new Map(); this.windows.set(minute, window); }
    const mapKey = endpoint ?? "";
    let counts = window.get(mapKey);
    if (!counts) { counts = empty(endpoint); window.set(mapKey, counts); }
    counts.decisions[decision.action === "ALLOW" ? "allow" : "block"]++;
    if ("staticVerdict" in decision) {
      const key = { SAFE: "safe", SUSPICIOUS: "suspicious", POLICY_VIOLATION: "policyViolation", ERROR: "error" } as const;
      counts.staticVerdicts[key[decision.staticVerdict.verdict]]++;
      if (decision.sampled) counts.jev.sampledSafe++;
      if (decision.jev) counts.jev[decision.jev.verdict === "ATTACK" ? "attack" : "benign"]++;
      else if (decision.reason.includes("JEV unavailable") || decision.reason.includes("JEV result invalid")) counts.jev.unavailable++;
      if (decision.reason.includes("error") || decision.reason.includes("unavailable") || decision.reason.includes("invalid")) counts.failureBehaviorApplied++;
    } else if (failureBehaviorApplied) {
      counts.failureBehaviorApplied++;
    }
  }

  start(): void {
    this.timer = setInterval(() => { void this.tick(); }, 60_000);
    this.timer.unref();
    void this.heartbeat();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.flush(true);
  }

  private async tick(): Promise<void> {
    await this.bundles.checkForUpdate();
    await Promise.allSettled([this.heartbeat(), this.flush()]);
  }

  private async heartbeat(): Promise<void> {
    try {
      const status = this.bundles.status;
      await this.post("api/v1/proxy/heartbeats", heartbeatSchema.parse({
        schemaVersion: HEARTBEAT_SCHEMA,
        instanceId: this.instanceId,
        proxyVersion: this.options.proxyVersion,
        supportedBundleSchemas: [BUNDLE_SCHEMA],
        supportedToolRegistries: [...SUPPORTED_TOOL_REGISTRIES],
        health: status.dashboardReachable ? "ok" : "degraded",
        tenants: [{ tenantId: this.options.tenantId, bundleSource: status.source, loadedBundleVersion: this.bundles.snapshot.version }],
      }));
    } catch {
      console.warn("[reporter] heartbeat failed");
    }
  }

  private async flush(includeCurrent = false): Promise<void> {
    if (this.sending) return;
    const latest = this.bundles.status;
    if (latest.pullFailures > this.lastEvents.pullFailures || latest.verificationFailures > this.lastEvents.verificationFailures || this.droppedWindows > 0) {
      const minute = Math.floor(Date.now() / 60_000) * 60_000;
      if (!this.windows.has(minute)) this.windows.set(minute, new Map());
    }
    const completed = [...this.windows.entries()].filter(([minute]) => includeCurrent || minute + 60_000 <= Date.now()).sort(([a], [b]) => a - b);
    if (completed.length === 0 && !this.pending) return;
    this.sending = true;
    const status = this.bundles.status;
    const events = {
      bundleVerificationFailures: Math.max(0, status.verificationFailures - this.lastEvents.verificationFailures),
      bundlePullFailures: Math.max(0, status.pullFailures - this.lastEvents.pullFailures),
      droppedWindows: this.droppedWindows,
    };
    const selected = completed.slice(0, 1_440);
    const windows = selected.map(([minute, entries], index) => ({
      tenantId: this.options.tenantId,
      bundleVersion: this.bundles.snapshot.version,
      windowStart: new Date(minute).toISOString(),
      endpoints: [...entries.values()],
      events: index === 0 ? events : { bundleVerificationFailures: 0, bundlePullFailures: 0, droppedWindows: 0 },
    }));
    try {
      this.pending ??= {
        body: telemetryBatchSchema.parse({ schemaVersion: TELEMETRY_SCHEMA, instanceId: this.instanceId, batchId: randomUUID(), windows }),
        minutes: selected.map(([minute]) => minute),
        pullFailures: status.pullFailures,
        verificationFailures: status.verificationFailures,
        droppedWindows: this.droppedWindows,
      };
      await this.post("api/v1/proxy/telemetry", this.pending.body);
      for (const minute of this.pending.minutes) this.windows.delete(minute);
      this.lastEvents = { pullFailures: this.pending.pullFailures, verificationFailures: this.pending.verificationFailures };
      this.droppedWindows = Math.max(0, this.droppedWindows - this.pending.droppedWindows);
      this.pending = undefined;
    } catch (error) {
      console.warn("[reporter] telemetry failed:", error);
      if (this.pending && error instanceof DashboardHttpError && error.status >= 400 && error.status < 500 && error.status !== 429) {
        for (const minute of this.pending.minutes) this.windows.delete(minute);
        this.droppedWindows += this.pending.minutes.length;
        this.pending = undefined;
      }
      if (this.windows.size > 1_440) {
        this.windows.delete([...this.windows.keys()].sort((a, b) => a - b)[0]!);
        this.droppedWindows++;
      }
    } finally { this.sending = false; }
  }

  private async post(path: string, body: unknown): Promise<void> {
    const url = new URL(path, this.options.apiBaseUrl.endsWith("/") ? this.options.apiBaseUrl : `${this.options.apiBaseUrl}/`);
    const response = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.options.deploymentKey}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new DashboardHttpError(response.status);
  }
}

class DashboardHttpError extends Error {
  constructor(readonly status: number) { super(`Dashboard returned ${status}`); }
}
