import { createHash } from "node:crypto";
import { canonicalJson, type PolicyStep, type SignedBundle } from "../../shared/contracts/bundle";
import { isToolId } from "../../shared/contracts/tools";
import type { ExecutionPlan, ToolStep } from "../static-analysis/runner";
import { createTool } from "../static-analysis";
import { ToolState, type ToolStateStores } from "../static-analysis/shared";

type Scope = "global" | "environment" | "endpoint";

/** Descriptions of legitimate traffic from the policy, handed to JEV as data. */
export interface PolicyContext {
  global?: string;
  environment?: string;
  endpoint?: string;
  fields?: { target: string; context: string }[];
}

/** Everything that applies to one request: the matched endpoint (or none) and the merged plan of every scope. */
export interface ResolvedPolicy {
  /** "METHOD /path" of the matched endpoint, or null when only global and environment policies apply. */
  key: string | null;
  plan: ExecutionPlan;
  upstreamPath: string;
  context: PolicyContext;
}

interface CompiledStep { key: string; step: ToolStep }
interface Route { key: string; method: string; segments: string[]; plan: ExecutionPlan; context: PolicyContext }

/** The scoped view of any bundle schema: a v2 bundle has endpoint steps only. */
interface ScopedPolicy {
  global: { steps: PolicyStep[]; jevContext: string | null };
  environment: { steps: PolicyStep[]; jevContext: string | null };
  endpoints: { method: string; path: string; steps: PolicyStep[]; jevContext: string | null; fieldContexts: { target: string; jevContext: string }[] }[];
}

function scoped(bundle: SignedBundle): ScopedPolicy {
  if (bundle.schemaVersion === "tessera.bundle/v3") return bundle.policy;
  return {
    global: { steps: [], jevContext: null },
    environment: { steps: [], jevContext: null },
    endpoints: bundle.policy.endpoints.map((endpoint) => ({ ...endpoint, jevContext: null, fieldContexts: [] })),
  };
}

const stepKey = (step: PolicyStep) => `${step.toolId}:${step.target ?? ""}`;

/**
 * Compiles a verified bundle into executable plans. Global and environment steps are built once and shared by every
 * route, so a global `rate_limit` counts across endpoints. When a tool and target appear in more than one scope, the
 * most specific scope wins: endpoint, then environment, then global.
 */
export class PolicySnapshot {
  private readonly routes: Route[];
  private readonly global: CompiledStep[];
  private readonly environment: CompiledStep[];
  private readonly unknownPlan: ExecutionPlan;
  private readonly scopeContext: PolicyContext;

  /** `stores` gives the tenant's Redis view, where tools that look across requests keep their state. */
  constructor(readonly bundle: SignedBundle, private readonly stores: ToolStateStores) {
    const policy = scoped(bundle);
    this.global = policy.global.steps.map((step) => ({ key: stepKey(step), step: this.step("global", "global", step) }));
    this.environment = policy.environment.steps.map((step) => ({ key: stepKey(step), step: this.step("environment", "environment", step) }));
    this.scopeContext = {
      ...(policy.global.jevContext ? { global: policy.global.jevContext } : {}),
      ...(policy.environment.jevContext ? { environment: policy.environment.jevContext } : {}),
    };
    this.unknownPlan = this.merge([]);
    this.routes = policy.endpoints.map((endpoint) => {
      const key = `${endpoint.method} ${endpoint.path}`;
      const own = endpoint.steps.map((step) => ({ key: stepKey(step), step: this.step("endpoint", key, step) }));
      return {
        key,
        method: endpoint.method,
        segments: endpoint.path.split("/").slice(1),
        plan: this.merge(own),
        context: {
          ...this.scopeContext,
          ...(endpoint.jevContext ? { endpoint: endpoint.jevContext } : {}),
          ...(endpoint.fieldContexts.length > 0
            ? { fields: endpoint.fieldContexts.map(({ target, jevContext }) => ({ target, context: jevContext })) }
            : {}),
        },
      };
    });
    this.routes.sort((a, b) => b.segments.filter((part) => !part.startsWith(":")).length - a.segments.filter((part) => !part.startsWith(":")).length);
  }

  get version(): string {
    return this.bundle.version;
  }

  /** Steps per scope, for operators; no configuration or context text. */
  get summary(): { global: number; environment: number; endpoints: number; endpointSteps: number } {
    const policy = scoped(this.bundle);
    return {
      global: policy.global.steps.length,
      environment: policy.environment.steps.length,
      endpoints: policy.endpoints.length,
      endpointSteps: policy.endpoints.reduce((total, endpoint) => total + endpoint.steps.length, 0),
    };
  }

  match(method: string, rawPath: string): ResolvedPolicy | undefined {
    const policyPath = this.routePath(rawPath);
    if (!policyPath) return undefined;
    const segments = policyPath.split("/").slice(1);
    const route = this.routes.find((candidate) => candidate.method === method &&
      candidate.segments.length === segments.length &&
      candidate.segments.every((part, index) => part.startsWith(":") ? segments[index] !== "" : part === segments[index]));
    return route && { key: route.key, plan: route.plan, upstreamPath: policyPath, context: route.context };
  }

  /** Global and environment policies for a request no endpoint policy matches. */
  matchUnknown(rawPath: string): ResolvedPolicy {
    return { key: null, plan: this.unknownPlan, upstreamPath: this.routePath(rawPath) ?? rawPath, context: this.scopeContext };
  }

  routePath(rawPath: string): string | undefined {
    const prefix = this.bundle.runtimeConfig.routing.pathPrefix.replace(/\/$/, "");
    if (prefix && (!rawPath.startsWith(prefix) || (rawPath.length > prefix.length && rawPath[prefix.length] !== "/"))) return undefined;
    return rawPath.slice(prefix.length) || "/";
  }

  private merge(endpoint: CompiledStep[]): ExecutionPlan {
    const taken = new Set(endpoint.map((entry) => entry.key));
    const environment = this.environment.filter((entry) => !taken.has(entry.key));
    for (const entry of environment) taken.add(entry.key);
    const global = this.global.filter((entry) => !taken.has(entry.key));
    return [...global, ...environment, ...endpoint].map((entry) => entry.step);
  }

  // Each step keeps its state under a namespace derived from its scope (the endpoint, or "global"/"environment") and
  // the step itself: two steps never share state, and an unchanged step keeps its windows across bundle updates and restarts.
  private step(scope: Scope, owner: string, step: PolicyStep): ToolStep {
    if (!isToolId(step.toolId)) throw new Error(`Unknown tool: ${step.toolId}`);
    const identity = scope === "endpoint" ? { endpoint: owner, step } : { scope, step };
    const namespace = createHash("sha256").update(canonicalJson(identity)).digest("hex").slice(0, 16);
    const tool = createTool(step.toolId, step.config, new ToolState(this.stores, `${step.toolId}:${namespace}`));
    if (tool.metadata.contextType !== step.contextType) throw new Error(`${step.toolId} runs on ${tool.metadata.contextType} context`);
    if (step.contextType === "full") return { tool } as ToolStep;
    if (step.target === undefined) throw new Error(`${step.toolId} needs a target`);
    return { tool, target: step.target } as ToolStep;
  }
}
