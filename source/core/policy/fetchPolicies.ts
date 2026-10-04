import type { SignedBundle } from "../../shared/contracts/bundle";
import type { BundleFetcher } from "./BundleFetcher";
import type { PolicySnapshot } from "./PolicySnapshot";
import type { PolicyStore } from "./PolicyStore";

export interface FetchPoliciesResult {
  status: "updated" | "unchanged";
  version: string | null;
  previousVersion: string | null;
  summary?: PolicySnapshot["summary"];
}

/**
 * What `tessera fetch` does: pull the active bundle, verify it, build every tool it names (so a bundle this proxy
 * cannot run is refused), and only then store it as active. Any failure leaves Redis as it was.
 */
export async function fetchPolicies(deps: {
  fetcher: BundleFetcher;
  store: PolicyStore;
  /** Builds the bundle's tools; throws when one cannot run here. */
  compile: (bundle: SignedBundle) => PolicySnapshot;
  /** Download even when Redis already holds the active version, e.g. to replace a damaged copy. */
  force?: boolean;
}): Promise<FetchPoliciesResult> {
  // a malformed pointer counts as nothing stored, so a fetch can replace it
  const previousVersion = await deps.store.activeVersion().catch(() => null);
  const bundle = await deps.fetcher.fetch(deps.force ? undefined : previousVersion ?? undefined);
  if (!bundle) return { status: "unchanged", version: previousVersion, previousVersion };
  const snapshot = deps.compile(bundle);
  if (bundle.version === previousVersion && !deps.force) {
    return { status: "unchanged", version: bundle.version, previousVersion, summary: snapshot.summary };
  }
  await deps.store.save(bundle, deps.force);
  return { status: "updated", version: bundle.version, previousVersion, summary: snapshot.summary };
}
