import { TypeSafeClient } from "@typesafe-ai/sdk";
import type { NormalizedRequest } from "../../shared/contracts";
import type { StaticVerdict } from "../static-analysis/aggregator";
import type { PolicyContext } from "../policy/PolicySnapshot";
import { JevClient, type DynamicVerdict, type VerdictStore } from "./client";
import { jevCredentialSchema } from "../../shared/contracts/operations";

/** Fetches an organization credential outside the request path and holds it only in memory. */
export class CredentialManager {
  private client?: JevClient;

  constructor(
    private readonly apiBaseUrl: string,
    private readonly deploymentKey: string,
    private readonly cacheForVersion: (version: number) => VerdictStore,
  ) {}

  get available(): boolean { return this.client !== undefined; }

  async refresh(): Promise<void> {
    try {
      const url = new URL("api/v1/proxy/jev-credential", this.apiBaseUrl.endsWith("/") ? this.apiBaseUrl : `${this.apiBaseUrl}/`);
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${this.deploymentKey}` },
        signal: AbortSignal.timeout(5000),
      });
      if (response.status === 404) { this.client = undefined; return; }
      if (!response.ok) throw new Error(`JEV credential API returned ${response.status}`);
      const credential = jevCredentialSchema.parse(await response.json());
      this.client = new JevClient(new TypeSafeClient({ apiKey: credential.apiKey }), this.cacheForVersion(credential.version));
    } catch {
      // A failed refresh preserves the current credential. Never log response bodies or key material.
      console.warn("[jev] credential refresh failed");
    }
  }

  createVerdict(request: NormalizedRequest, staticAnalysis: StaticVerdict, context?: PolicyContext): Promise<DynamicVerdict> {
    if (!this.client) return Promise.reject(new Error("JEV credential unavailable"));
    return this.client.createVerdict(request, staticAnalysis, context);
  }
}
