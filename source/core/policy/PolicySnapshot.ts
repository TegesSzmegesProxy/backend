import type { SignedBundle } from "../../shared/contracts/bundle";
import type { ExecutionPlan } from "../static-analysis/runner";
import { StringLength } from "../static-analysis";

interface Route { key: string; method: string; segments: string[]; plan: ExecutionPlan }

/** Compiles only tools in the local executable registry from a verified bundle. */
export class PolicySnapshot {
  private readonly routes: Route[];

  constructor(readonly bundle: SignedBundle) {
    this.routes = bundle.policy.endpoints.map((endpoint) => ({
      key: `${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      segments: endpoint.path.split("/").slice(1),
      plan: endpoint.steps.map((step) => ({ tool: new StringLength(step.config), target: step.target })),
    }));
    this.routes.sort((a, b) => b.segments.filter((part) => !part.startsWith(":")).length - a.segments.filter((part) => !part.startsWith(":")).length);
  }

  match(method: string, rawPath: string): { key: string; plan: ExecutionPlan; upstreamPath: string } | undefined {
    const policyPath = this.routePath(rawPath);
    if (!policyPath) return undefined;
    const segments = policyPath.split("/").slice(1);
    const route = this.routes.find((candidate) => candidate.method === method &&
      candidate.segments.length === segments.length &&
      candidate.segments.every((part, index) => part.startsWith(":") ? segments[index] !== "" : part === segments[index]));
    return route && { key: route.key, plan: route.plan, upstreamPath: policyPath };
  }

  routePath(rawPath: string): string | undefined {
    const prefix = this.bundle.runtimeConfig.routing.pathPrefix.replace(/\/$/, "");
    if (prefix && (!rawPath.startsWith(prefix) || (rawPath.length > prefix.length && rawPath[prefix.length] !== "/"))) return undefined;
    return rawPath.slice(prefix.length) || "/";
  }
}
