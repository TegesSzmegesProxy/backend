import { SUPPORTED_BUNDLE_SCHEMAS, SUPPORTED_TOOL_REGISTRIES, type BundleVerifier, type SignedBundle } from "../../shared/contracts/bundle";

export interface BundleFetcherOptions { tenantId: string; apiBaseUrl: string; deploymentKey: string }

/** The dashboard served a bundle that failed verification; it is never stored or run. */
export class BundleVerificationError extends Error {
  constructor(cause: unknown) {
    super(`Bundle failed verification: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "BundleVerificationError";
  }
}

/** Pulls the tenant's active bundle from the control plane and verifies it. Never stores or applies it. */
export class BundleFetcher {
  constructor(private readonly options: BundleFetcherOptions, private readonly verifier: BundleVerifier) {}

  /** The verified active bundle, or undefined when it is still `currentVersion` (304). */
  async fetch(currentVersion?: string): Promise<SignedBundle | undefined> {
    const base = this.options.apiBaseUrl.endsWith("/") ? this.options.apiBaseUrl : `${this.options.apiBaseUrl}/`;
    const url = new URL(`api/v1/tenants/${this.options.tenantId}/active-bundle`, base);
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.options.deploymentKey}`,
        "Tessera-Bundle-Schemas": SUPPORTED_BUNDLE_SCHEMAS.join(", "),
        "Tessera-Tool-Registries": SUPPORTED_TOOL_REGISTRIES.join(", "),
        ...(currentVersion ? { "If-None-Match": `"${currentVersion}"` } : {}),
      },
      signal: AbortSignal.timeout(5000),
    });
    if (response.status === 304) return undefined;
    if (!response.ok) throw new Error(`Bundle API returned ${response.status}${await reason(response)}`);
    let raw: unknown;
    try { raw = await response.json(); } catch { throw new Error("Bundle response is not JSON"); }
    let bundle: SignedBundle;
    try { bundle = this.verifier.verify(raw); } catch (error) { throw new BundleVerificationError(error); }
    const etag = response.headers.get("etag");
    if (etag && etag !== `"${bundle.version}"`) throw new BundleVerificationError(new Error("ETag does not match version"));
    return bundle;
  }
}

/** The control plane's `message`, never the body: it explains 404 (nothing activated) and 406 (incompatible). */
async function reason(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { message?: unknown };
    const message = [body.message].flat().filter((part): part is string => typeof part === "string").join("; ");
    return message ? `: ${message.slice(0, 300)}` : "";
  } catch {
    return "";
  }
}
