import type { TenantRedis } from "../../shared/storage";
import type { SignedBundle } from "../../shared/contracts/bundle";

const VERSION = /^[a-f0-9]{64}$/;
const ACTIVE = "active";
const PREVIOUS = "previous";
const UPDATES = "updates";
const bundleKey = (version: string) => `bundle:${version}`;

/** Startup found nothing `tessera fetch` stored. */
export class PoliciesNotFetchedError extends Error {
  constructor(tenantId: string) {
    super(`No Tessera policies found in Redis for tenant ${tenantId}. Run \`tessera fetch\`, then start the proxy again.`);
    this.name = "PoliciesNotFetchedError";
  }
}

/**
 * The fetched signed bundle in Redis, under `tessera:{tenantId}:policy:`:
 * - `bundle:{version}`: the signed bundle exactly as the dashboard served it;
 * - `active`: the version Ingress runs; `previous`: the one it replaced, kept for rollback.
 * Only `tessera fetch` writes here, after verifying the bundle. Redis content is still untrusted: every reader
 * verifies the signature again before using it.
 */
export class PolicyStore {
  constructor(private readonly redis: TenantRedis) {}

  async activeVersion(): Promise<string | null> {
    const version = await this.redis.get(ACTIVE);
    if (version === null) return null;
    if (!VERSION.test(version)) throw new Error("Stored active policy version is malformed; run `tessera fetch`");
    return version;
  }

  /** The raw active bundle, or null when nothing was fetched. */
  async loadActive(): Promise<unknown | null> {
    const version = await this.activeVersion();
    if (version === null) return null;
    const raw = await this.redis.get(bundleKey(version));
    if (raw === null) throw new Error(`Stored active policy ${version} is missing; run \`tessera fetch\``);
    try {
      return JSON.parse(raw) as unknown;
    } catch {
      throw new Error(`Stored active policy ${version} is not JSON; run \`tessera fetch\``);
    }
  }

  /**
   * Stores a verified bundle and makes it active in one MULTI, then announces it to running proxies. The active
   * version is rewritten only with `overwrite`, which repairs a damaged copy.
   */
  async save(bundle: SignedBundle, overwrite = false): Promise<void> {
    let current: string | null;
    try {
      current = await this.activeVersion();
    } catch {
      current = null; // a malformed pointer is replaced
    }
    if (current === bundle.version && !overwrite) return;
    const previous = await this.redis.get(PREVIOUS);
    const sets: [string, string][] = [[bundleKey(bundle.version), JSON.stringify(bundle)], [ACTIVE, bundle.version]];
    if (current && current !== bundle.version) sets.push([PREVIOUS, current]);
    const stale = previous && VERSION.test(previous) && previous !== bundle.version && previous !== current ? [bundleKey(previous)] : [];
    await this.redis.transaction(sets, stale);
    await this.redis.publish(UPDATES, bundle.version);
  }

  /** Calls `listener` with each newly activated version. */
  watch(listener: (version: string) => void): Promise<() => Promise<void>> {
    return this.redis.subscribe(UPDATES, (message) => { if (VERSION.test(message)) listener(message); });
  }
}
