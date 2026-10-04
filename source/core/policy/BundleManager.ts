import { readFile, mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { BUNDLE_SCHEMA, SUPPORTED_TOOL_REGISTRIES, BundleVerifier, type SignedBundle } from "../../shared/contracts/bundle";

export type BundleSource = "remote" | "last_known_good";

/** Owns the immutable runtime snapshot and the verified local recovery copy. */
export class BundleManager {
  private active?: SignedBundle;
  private source?: BundleSource;
  private etag?: string;
  private restartRequired = false;
  private dashboardReachable = false;
  private pullFailures = 0;
  private verificationFailures = 0;

  constructor(
    private readonly options: { tenantId: string; apiBaseUrl: string; deploymentKey: string; cacheFile: string },
    private readonly verifier: BundleVerifier,
  ) {}

  get snapshot(): SignedBundle {
    if (!this.active) throw new Error("No verified bundle loaded");
    return this.active;
  }

  get status() {
    return {
      source: this.source,
      restartRequired: this.restartRequired,
      dashboardReachable: this.dashboardReachable,
      pullFailures: this.pullFailures,
      verificationFailures: this.verificationFailures,
    };
  }

  async start(): Promise<SignedBundle> {
    let remote: SignedBundle | undefined;
    try {
      remote = await this.fetchBundle();
      this.dashboardReachable = true;
      if (remote) {
        await this.save(remote);
        this.active = remote;
        this.source = "remote";
        return remote;
      }
    } catch (error) {
      this.dashboardReachable = false;
      this.pullFailures++;
      console.warn("[bundle] pull failed; trying verified local copy:", error);
    }
    const local = await this.loadLocal();
    if (!local) throw new Error("No valid bundle available at startup");
    this.active = local;
    this.source = "last_known_good";
    return local;
  }

  async checkForUpdate(): Promise<void> {
    if (!this.active) return;
    try {
      const fetched = await this.fetchBundle(this.etag ?? `"${this.active.version}"`);
      this.dashboardReachable = true;
      if (fetched && fetched.version !== this.active.version) {
        // A restart is required to switch the request path to the new policy.
        await this.save(fetched);
        this.restartRequired = true;
        console.info(`[bundle] verified newer version ${fetched.version}; restart required`);
      }
    } catch (error) {
      this.dashboardReachable = false;
      this.pullFailures++;
      console.warn("[bundle] update check failed:", error);
    }
  }

  private async fetchBundle(ifNoneMatch?: string): Promise<SignedBundle | undefined> {
    const url = new URL(`api/v1/tenants/${this.options.tenantId}/active-bundle`, this.options.apiBaseUrl.endsWith("/") ? this.options.apiBaseUrl : `${this.options.apiBaseUrl}/`);
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.options.deploymentKey}`,
        "Tessera-Bundle-Schemas": BUNDLE_SCHEMA,
        "Tessera-Tool-Registries": SUPPORTED_TOOL_REGISTRIES.join(", "),
        ...(ifNoneMatch ? { "If-None-Match": ifNoneMatch } : {}),
      },
      signal: AbortSignal.timeout(5000),
    });
    if (response.status === 304) return undefined;
    if (!response.ok) throw new Error(`Bundle API returned ${response.status}`);
    let raw: unknown;
    try { raw = await response.json(); } catch { throw new Error("Bundle response is not JSON"); }
    let bundle: SignedBundle;
    try { bundle = this.verifier.verify(raw); }
    catch (error) { this.verificationFailures++; throw error; }
    const etag = response.headers.get("etag");
    if (etag && etag !== `"${bundle.version}"`) {
      this.verificationFailures++;
      throw new Error("Bundle ETag does not match version");
    }
    this.etag = etag ?? `"${bundle.version}"`;
    return bundle;
  }

  private async loadLocal(): Promise<SignedBundle | undefined> {
    try {
      return this.verifier.verify(JSON.parse(await readFile(this.options.cacheFile, "utf8")));
    } catch (error) {
      console.warn("[bundle] local copy unavailable or invalid:", error);
      return undefined;
    }
  }

  private async save(bundle: SignedBundle): Promise<void> {
    const dir = dirname(this.options.cacheFile);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const temporary = `${this.options.cacheFile}.${randomUUID()}.tmp`;
    try {
      const file = await open(temporary, "wx", 0o600);
      try { await file.writeFile(JSON.stringify(bundle)); await file.sync(); }
      finally { await file.close(); }
      await rename(temporary, this.options.cacheFile);
      const directory = await open(dir, "r");
      try { await directory.sync(); } finally { await directory.close(); }
    } catch (error) {
      await unlink(temporary).catch(() => undefined);
      throw error;
    }
  }
}
