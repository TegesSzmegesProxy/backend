import { z } from "zod";

// Building blocks for tool configuration contracts. Every value here arrives from the control plane inside a
// signed bundle, so each one is bounded: a contract describes what the proxy will accept, not just the shape.

export type ToolCategoryName = "schema" | "auth" | "injection" | "url" | "resource" | "anomaly" | "protocol" | "bot" | "data_leakage";
export type ToolContextTypeName = "field" | "file" | "full";

export interface ToolContract<Id extends string = string, Context extends ToolContextTypeName = ToolContextTypeName, Config extends z.ZodType = z.ZodType> {
  id: Id;
  displayName: string;
  category: ToolCategoryName;
  contextType: Context;
  description: string;
  config: Config;
}

export function defineTool<const Id extends string, const Context extends ToolContextTypeName, Config extends z.ZodType>(
  contract: ToolContract<Id, Context, Config>,
): ToolContract<Id, Context, Config> {
  return contract;
}

/** Contract of a tool that takes no configuration: only an empty object is accepted. */
export const noConfig = () => z.strictObject({});

export const count = (max = 1_000_000) => z.number().int().min(0).max(max);
export const positiveCount = (max = 1_000_000) => z.number().int().min(1).max(max);
/** Durations in milliseconds, at most one day. */
export const durationMs = (max = 86_400_000) => z.number().int().min(1).max(max);
export const ratio = () => z.number().finite().min(0).max(1);
export const bytes = (max = 1_073_741_824) => z.number().int().min(0).max(max);

export const list = <T extends z.ZodType>(item: T, max = 1000) => z.array(item).max(max);
export const name = (max = 128) => z.string().min(1).max(max);
export const names = (max = 1000) => list(name(), max);

/**
 * Field names as the tools compare them: the last path segment, lowercased, without "_" and "-"
 * ("user[return_url]" and "returnUrl" are both "returnurl").
 */
export const fieldNames = (max = 1000) => list(name().regex(/^[a-z0-9]+$/, "lowercase letters and digits only"), max);

/** Lowercase header names. */
export const headerName = () => name().regex(/^[a-z0-9!#$%&'*+.^_`|~-]+$/, "lowercase header name");
export const headerNames = (max = 200) => list(headerName(), max);

/** Lowercase path prefixes: "/admin" also covers "/admin/users". */
export const route = () => z.string().max(1024).regex(/^\/[^?#\s]*$/, "lowercase path without query").refine((value) => value === value.toLowerCase(), "lowercase path");
export const routes = (max = 500) => list(route(), max);
/**
 * Route prefixes a check is limited to. Omitted, the check covers every request of the endpoints its step is
 * attached to, which is the normal case: the policy already decides which endpoints run which tools.
 */
export const routeFilter = () => routes().optional()
  .describe("Route prefixes the check is limited to. Omitted, every endpoint the step is attached to.");

export const httpMethod = () => z.string().min(1).max(20).regex(/^[A-Z]+$/, "uppercase method");
export const httpMethods = () => list(httpMethod(), 20);

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
export const ipv4 = () => z.string().regex(IPV4, "IPv4 address");
/** IPv4 CIDR ("10.0.0.0/8"); IPv6 networks never match in the current tools, so they are rejected. */
export const cidr = () => z.string().max(18).refine((value) => {
  const [address, bits, ...rest] = value.split("/");
  return rest.length === 0 && IPV4.test(address) && (bits === undefined || (/^\d{1,2}$/.test(bits) && Number(bits) <= 32));
}, "IPv4 CIDR");
export const cidrs = (max = 10_000) => list(cidr(), max);

export const hostname = () => z.string().min(1).max(253).regex(/^[a-z0-9.-]+$/, "lowercase hostname");
export const hostnames = (max = 1000) => list(hostname(), max);
export const origin = () => z.string().max(2048).refine((value) => {
  try { return new URL(value).origin === value; } catch { return false; }
}, "origin such as https://example.com");
export const origins = (max = 500) => list(origin(), max);

export const countryCode = () => z.string().regex(/^[A-Z]{2}$/, "ISO 3166-1 alpha-2 code");
export const countryCodes = () => list(countryCode(), 250);

/** A regular expression source. It must compile; it runs against bounded input only. */
export const regexSource = (max = 1024) => z.string().min(1).max(max).refine((value) => {
  try { new RegExp(value); return true; } catch { return false; }
}, "valid regular expression");
export const regexFlags = () => z.string().regex(/^[imsu]*$/, "only i, m, s and u flags").max(4);

/** Two escalating limits: above `suspicious` JEV decides, above `block` the request is rejected. */
export const escalation = (defaults: { suspicious: number; block: number }, max = 1_000_000) => z.strictObject({
  suspicious: count(max).default(defaults.suspicious),
  block: count(max).default(defaults.block),
}).refine((value) => value.suspicious <= value.block, "suspicious must not exceed block")
  .default(defaults);

/** Geo-IP database: the location of each network. */
export const geoIpTable = () => list(z.strictObject({
  cidr: cidr(),
  country: countryCode(),
  city: z.string().max(100),
  lat: z.number().min(-90).max(90),
  lon: z.number().min(-180).max(180),
}), 100_000);
