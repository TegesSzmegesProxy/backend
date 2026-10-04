import type { ActivePolicy } from "./ActivePolicy";
import type { PolicySnapshot } from "./PolicySnapshot";
import type { PolicyStore } from "./PolicyStore";

const POLL_INTERVAL_MS = 30_000;

/**
 * Applies what `tessera fetch` stores while the proxy runs. It listens for the fetch's announcement and polls the
 * active pointer as a fallback, because Redis drops messages published while a subscriber is disconnected. A version
 * that fails to load, verify or compile never replaces the running policy, and is not retried until another is fetched.
 */
export class PolicyWatcher {
  private timer?: NodeJS.Timeout;
  private unsubscribe?: () => Promise<void>;
  private running?: Promise<void>;
  private again = false;
  private skipped?: string;

  constructor(
    private readonly store: PolicyStore,
    private readonly active: ActivePolicy,
    /** Verifies and compiles a stored bundle; throws when it cannot run. */
    private readonly load: (raw: unknown) => PolicySnapshot,
    private readonly pollIntervalMs = POLL_INTERVAL_MS,
  ) {}

  async start(): Promise<void> {
    try {
      this.unsubscribe = await this.store.watch(() => { void this.check(); });
    } catch (error) {
      console.warn("[policy] update channel unavailable; polling only:", error instanceof Error ? error.message : error);
    }
    this.timer = setInterval(() => { void this.check(); }, this.pollIntervalMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.unsubscribe?.();
    await this.running;
  }

  /** One reload at a time; a request made during one runs once more after it. */
  check(): Promise<void> {
    if (this.running) {
      this.again = true;
      return this.running;
    }
    this.running = (async () => {
      do {
        this.again = false;
        await this.reload();
      } while (this.again);
    })().finally(() => { this.running = undefined; });
    return this.running;
  }

  private async reload(): Promise<void> {
    let version: string | null;
    try {
      version = await this.store.activeVersion();
    } catch (error) {
      // Redis being down never drops the policy in memory.
      console.warn("[policy] cannot read the stored policy version:", error instanceof Error ? error.message : error);
      return;
    }
    if (!version || version === this.active.snapshot.version || version === this.skipped) return;
    try {
      const raw = await this.store.loadActive();
      if (raw === null) return;
      const next = this.load(raw);
      if (this.active.swap(next)) {
        console.info(`[policy] switched to fetched policy ${next.version}`);
      } else {
        this.skipped = version;
        console.warn(`[policy] fetched policy ${version} changes the upstream; restart the proxy to apply it`);
      }
    } catch (error) {
      this.skipped = version;
      this.active.recordReloadFailure();
      console.error(`[policy] fetched policy ${version} rejected; keeping ${this.active.snapshot.version}:`, error instanceof Error ? error.message : error);
    }
  }
}
