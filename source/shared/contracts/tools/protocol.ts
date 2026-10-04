import { z } from "zod";
import { cidrs, defineTool, headerNames, hostnames, noConfig, origins, positiveCount } from "./common";

const allowedHosts = () => hostnames().min(1).describe("Hostnames the application is served under, lowercase, without port.");

export const protocolTools = {
  absolute_uri_request: defineTool({
    id: "absolute_uri_request",
    displayName: "Absolute URI in request line",
    category: "protocol",
    contextType: "full",
    description: "Rejects authority-form, asterisk-form and foreign absolute-form request targets; flags absolute-form to the own host.",
    config: z.strictObject({
      allowedHosts: allowedHosts(),
    }),
  }),
  chunked_encoding_anomaly: defineTool({
    id: "chunked_encoding_anomaly",
    displayName: "Chunked encoding anomaly",
    category: "protocol",
    contextType: "full",
    description: "Rejects malformed or oversized chunk sizes, chunk extensions and forbidden trailer fields.",
    config: z.strictObject({
      maxChunkSizeDigits: positiveCount(64).default(16).describe("Longer size fields are valid hex but parse differently across stacks."),
      maxExtensionBytes: positiveCount(1_048_576).default(1024).describe("Chunk extensions are a known DoS vector (unbounded buffering)."),
      maxChunks: positiveCount(10_000_000).default(10_000),
    }),
  }),
  duplicate_headers: defineTool({
    id: "duplicate_headers",
    displayName: "Duplicate headers",
    category: "protocol",
    contextType: "full",
    description: "Detects repeated headers that must appear only once, which hops resolve differently.",
    config: noConfig(),
  }),
  hop_by_hop_abuse: defineTool({
    id: "hop_by_hop_abuse",
    displayName: "Hop-by-hop header abuse",
    category: "protocol",
    contextType: "full",
    description: "Detects Connection headers that name end-to-end or security headers so a hop strips them.",
    config: noConfig(),
  }),
  host_header_injection: defineTool({
    id: "host_header_injection",
    displayName: "Host header injection",
    category: "protocol",
    contextType: "full",
    description: "Rejects missing, malformed or foreign Host headers and foreign alternate host headers; flags mismatches.",
    config: z.strictObject({
      allowedHosts: allowedHosts(),
      alternateHostHeaders: headerNames().default(["x-forwarded-host", "x-host", "x-forwarded-server", "x-original-host", "x-http-host-override"]).describe("Headers that override or accompany Host in some frameworks (password-reset links, absolute redirects)."),
    }),
  }),
  invalid_header_chars: defineTool({
    id: "invalid_header_chars",
    displayName: "Invalid header characters",
    category: "protocol",
    contextType: "full",
    description: "Detects header names and values containing characters HTTP does not allow.",
    config: noConfig(),
  }),
  request_smuggling: defineTool({
    id: "request_smuggling",
    displayName: "Request smuggling",
    category: "protocol",
    contextType: "full",
    description: "Detects conflicting or obfuscated Content-Length and Transfer-Encoding framing.",
    config: noConfig(),
  }),
  websocket_origin: defineTool({
    id: "websocket_origin",
    displayName: "WebSocket origin",
    category: "protocol",
    contextType: "full",
    description: "Rejects WebSocket upgrades from foreign origins (cross-site WebSocket hijacking); flags missing origins.",
    config: z.strictObject({
      allowedOrigins: origins().min(1),
    }),
  }),
  x_forwarded_for_spoofing: defineTool({
    id: "x_forwarded_for_spoofing",
    displayName: "X-Forwarded-For spoofing",
    category: "protocol",
    contextType: "full",
    description: "Flags client-IP headers set by anyone but a trusted proxy, malformed or overlong chains and claimed internal addresses.",
    config: z.strictObject({
      trustedProxies: cidrs(1000).default([]).describe("Proxies allowed to set X-Forwarded-For and client-IP headers."),
      maxChain: positiveCount(1000).default(10),
      clientIpHeaders: headerNames().default(["x-real-ip", "true-client-ip", "x-client-ip", "cf-connecting-ip", "x-cluster-client-ip", "fastly-client-ip", "x-originating-ip"]).describe("Headers applications read as \"the real client IP\"."),
    }),
  }),
} as const;
