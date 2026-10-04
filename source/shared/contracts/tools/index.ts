import { z } from "zod";
import type { ToolContract } from "./common";
import { anomalyTools } from "./anomaly";
import { authTools } from "./auth";
import { botTools } from "./bot";
import { dataLeakageTools } from "./dataLeakage";
import { injectionTools } from "./injection";
import { protocolTools } from "./protocol";
import { resourceTools } from "./resource";
import { schemaTools } from "./schema";
import { urlTools } from "./url";

export type { ToolCategoryName, ToolContextTypeName, ToolContract } from "./common";

/** Registry version of the tool set below. Adding or changing a contract requires a new version. */
export const TOOL_REGISTRY_V2 = "tessera.tools/v2";

/**
 * Every tool the proxy can execute: its id, metadata and configuration contract. Shared by the proxy and
 * the control plane's compiler, so both validate policies against the same definitions.
 */
export const TOOL_CONTRACTS = {
  ...schemaTools,
  ...anomalyTools,
  ...authTools,
  ...botTools,
  ...dataLeakageTools,
  ...injectionTools,
  ...protocolTools,
  ...resourceTools,
  ...urlTools,
} as const;

export type ToolId = keyof typeof TOOL_CONTRACTS;
/** Configuration as a tool receives it, with defaults applied. */
export type ToolConfig<Id extends ToolId> = z.output<(typeof TOOL_CONTRACTS)[Id]["config"]>;
/** Configuration as a policy may send it; fields with defaults may be omitted. */
export type ToolConfigInput<Id extends ToolId> = z.input<(typeof TOOL_CONTRACTS)[Id]["config"]>;

export const TOOL_IDS = Object.keys(TOOL_CONTRACTS) as ToolId[];

export function isToolId(value: unknown): value is ToolId {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(TOOL_CONTRACTS, value);
}

export function toolContract(id: ToolId): ToolContract {
  return TOOL_CONTRACTS[id];
}

/** Validates a tool configuration and applies its defaults. Throws a ZodError when it breaks the contract. */
export function parseToolConfig<Id extends ToolId>(id: Id, config: unknown): ToolConfig<Id> {
  return TOOL_CONTRACTS[id].config.parse(config) as ToolConfig<Id>;
}

/** The configuration a tool runs with when a policy sets nothing; throws for tools with required settings. */
export function defaultToolConfig<Id extends ToolId>(id: Id): ToolConfig<Id> {
  return parseToolConfig(id, {});
}

/** The machine-readable registry published as docs/tool-registry.json: metadata plus JSON Schema per tool. */
export function toolRegistryDocument() {
  return {
    registryVersion: TOOL_REGISTRY_V2,
    tools: TOOL_IDS.map((id) => {
      const contract = toolContract(id);
      return {
        id: contract.id,
        displayName: contract.displayName,
        category: contract.category,
        contextType: contract.contextType,
        description: contract.description,
        // "input": what a policy may send, so settings with defaults are not listed as required
        config: z.toJSONSchema(contract.config, { io: "input", unrepresentable: "any" }),
      };
    }),
  };
}
