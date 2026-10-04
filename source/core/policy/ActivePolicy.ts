import type { BundleFetcher } from "./BundleFetcher";
import { BundleVerificationError } from "./BundleFetcher";
import type { PolicySnapshot } from "./PolicySnapshot";

/** Where the running policy came from. Policies are loaded from Redis, the last-known-good store `tessera fetch` fills. */
export type BundleSource = "remote" | "last_known_good";

export interface PolicyStatus {
  source: BundleSource;
  /** A fetched policy changed something the running server was built with (the upstream); restart to apply it. */
  restartRequired: boolean;
  /** The dashboard has activated a newer bundle than the one running; `tessera fetch` applies it. */
  updateAvailable: boolean;
  dashboardReachable: boolean;
  pullFailures: number;
  verificationFailures: number;
  reloadFailures: number;
}

/** What the reporter reads; implemented by `ActivePolicy`. */
export interface PolicyStatusSource {
  readonly snapshot: { readonly version: string };
  readonly status: PolicyStatus;
  checkForUpdate(): Promise<void>;
}

/**
 * Holds the policy the request path runs. Ingress reads `snapshot` once per request, so a request never mixes two
 * versions; `swap` replaces it atomically. Nothing here fetches or applies a bundle on its own: the update check only
 * reports that the dashboard has a newer one.
 */
export class ActivePolicy implements PolicyStatusSource {
  private current: PolicySnapshot;
  private restartRequired = false;
  private updateAvailable = false;
  private dashboardReachable = false;
  private pullFailures = 0;
  private verificationFailures = 0;
  private reloadFailures = 0;

  constructor(snapshot: PolicySnapshot, private readonly fetcher?: BundleFetcher) {
    this.current = snapshot;
  }

  get snapshot(): PolicySnapshot {
    return this.current;
  }

  get status(): PolicyStatus {
    return {
      source: "last_known_good",
      restartRequired: this.restartRequired,
      updateAvailable: this.updateAvailable,
      dashboardReachable: this.dashboardReachable,
      pullFailures: this.pullFailures,
      verificationFailures: this.verificationFailures,
      reloadFailures: this.reloadFailures,
    };
  }

  /**
   * Switches to `next` unless it changes the upstream, which the server is built with; then the running policy stays
   * and a restart is required. Returns whether it switched.
   */
  swap(next: PolicySnapshot): boolean {
    if (next.bundle.runtimeConfig.upstreamUrl !== this.current.bundle.runtimeConfig.upstreamUrl) {
      this.restartRequired = true;
      return false;
    }
    this.current = next;
    return true;
  }

  recordReloadFailure(): void {
    this.reloadFailures++;
  }

  /** Report-only: never stores or applies what it sees. */
  async checkForUpdate(): Promise<void> {
    if (!this.fetcher) return;
    try {
      const fetched = await this.fetcher.fetch(this.current.version);
      this.dashboardReachable = true;
      const available = fetched !== undefined && fetched.version !== this.current.version;
      if (available && !this.updateAvailable) console.info(`[policy] dashboard has a newer bundle ${fetched.version}; run \`tessera fetch\` to apply it`);
      this.updateAvailable = available;
    } catch (error) {
      if (error instanceof BundleVerificationError) {
        this.dashboardReachable = true;
        this.verificationFailures++;
      } else {
        this.dashboardReachable = false;
        this.pullFailures++;
      }
      console.warn("[policy] update check failed:", error instanceof Error ? error.message : error);
    }
  }
}
