import { createHash } from "node:crypto";
import { canonicalJson, type PolicyStep, type SignedBundle } from "../../shared/contracts/bundle";
import { isToolId } from "../../shared/contracts/tools";
import type { ExecutionPlan, ToolStep } from "../static-analysis/runner";
import { createTool } from "../static-analysis";
import { ToolState, type ToolStateStores } from "../static-analysis/shared";

interface Route { key: string; method: string; segments: string[]; plan: ExecutionPlan }

/** Compiles only tools in the local executable registry from a verified bundle. */
export class PolicySnapshot {
  private readonly routes: Route[];

  /** `stores` gives the tenant's Redis view, where tools that look across requests keep their state. */
  constructor(readonly bundle: SignedBundle, private readonly stores: ToolStateStores) {
    this.routes = bundle.policy.endpoints.map((endpoint) => ({
      key: `${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      segments: endpoint.path.split("/").slice(1),
      plan: endpoint.steps.map((step) => this.step(`${endpoint.method} ${endpoint.path}`, step)),
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

  // Each step keeps its state under a namespace derived from the endpoint and the step itself: two steps never
  // share state, and an unchanged step keeps its windows across bundle updates and restarts.
  private step(endpoint: string, step: PolicyStep): ToolStep {
    if (!isToolId(step.toolId)) throw new Error(`Unknown tool: ${step.toolId}`);
    const namespace = createHash("sha256").update(canonicalJson({ endpoint, step })).digest("hex").slice(0, 16);
    const tool = createTool(step.toolId, step.config, new ToolState(this.stores, `${step.toolId}:${namespace}`));
    if (tool.metadata.contextType !== step.contextType) throw new Error(`${step.toolId} runs on ${tool.metadata.contextType} context`);
    if (step.contextType === "full") return { tool } as ToolStep;
    if (step.target === undefined) throw new Error(`${step.toolId} needs a target`);
    return { tool, target: step.target } as ToolStep;
  }

  routePath(rawPath: string): string | undefined {
    const prefix = this.bundle.runtimeConfig.routing.pathPrefix.replace(/\/$/, "");
    if (prefix && (!rawPath.startsWith(prefix) || (rawPath.length > prefix.length && rawPath[prefix.length] !== "/"))) return undefined;
    return rawPath.slice(prefix.length) || "/";
  }
}
