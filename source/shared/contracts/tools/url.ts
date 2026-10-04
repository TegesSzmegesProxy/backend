import { z } from "zod";
import { cidrs, defineTool, fieldNames, hostname, hostnames, ipv4, list, name, noConfig, positiveCount, routes } from "./common";

export const urlTools = {
  cache_poisoning: defineTool({
    id: "cache_poisoning",
    displayName: "Cache poisoning",
    category: "url",
    contextType: "full",
    description: "Flags unkeyed forwarding and path-override headers from clients, and GET requests with a body.",
    config: z.strictObject({
      trustedProxies: cidrs(1000).default([]).describe("Proxies that legitimately add forwarding headers."),
    }),
  }),
  cloud_metadata: defineTool({
    id: "cloud_metadata",
    displayName: "Cloud metadata endpoint",
    category: "url",
    contextType: "field",
    description: "Detects URLs pointing at cloud instance metadata services, in any address notation.",
    config: noConfig(),
  }),
  dns_rebinding: defineTool({
    id: "dns_rebinding",
    displayName: "DNS rebinding",
    category: "url",
    contextType: "field",
    description: "Flags hosts of rebinding services and hosts known to resolve to private addresses.",
    config: z.strictObject({
      knownAnswers: list(z.strictObject({ host: hostname(), addresses: list(ipv4(), 50).min(1) }), 10_000).default([]).describe("Known DNS answers. Tools run synchronously and cannot resolve names, so only hosts listed here are judged by their addresses."),
    }),
  }),
  idn_homograph: defineTool({
    id: "idn_homograph",
    displayName: "IDN homograph",
    category: "url",
    contextType: "field",
    description: "Flags hosts mixing scripts or built from look-alike characters, especially ones imitating protected domains.",
    config: z.strictObject({
      protectedDomains: hostnames().default([]).describe("Own domains and brands whose look-alikes are reported."),
    }),
  }),
  ip_obfuscation: defineTool({
    id: "ip_obfuscation",
    displayName: "IP address obfuscation",
    category: "url",
    contextType: "field",
    description: "Detects IP addresses written in decimal, octal, hex or other notations that evade allowlists.",
    config: noConfig(),
  }),
  open_redirect: defineTool({
    id: "open_redirect",
    displayName: "Open redirect",
    category: "url",
    contextType: "field",
    description: "Flags redirect parameters pointing to foreign hosts, dangerous schemes or URLs with embedded credentials.",
    config: z.strictObject({
      allowedHosts: hostnames().min(1).describe("Hosts a redirect may point to; subdomains are allowed too (\"app.example.com\" matches \"example.com\")."),
      redirectFields: fieldNames().default([
        "redirect", "redirecturi", "redirecturl", "redirectto", "return", "returnto", "returnurl", "returnuri",
        "returnpath", "next", "nexturl", "continue", "dest", "destination", "goto", "forward", "target", "callback",
        "callbackurl", "successurl", "failureurl", "cancelurl", "back", "backurl", "rurl", "postlogin", "postlogout",
      ]).describe("Fields holding a redirect target. A generic \"url\" is left out: most URL fields are not redirects."),
    }),
  }),
  path_normalization: defineTool({
    id: "path_normalization",
    displayName: "Path normalization",
    category: "url",
    contextType: "full",
    description: "Flags paths that normalize differently across stacks; rejects ones that resolve to a privileged route.",
    config: z.strictObject({
      privilegedRoutes: routes().default([]).describe("Routes an access-control layer protects, so a disguised path reaching them is a bypass attempt."),
    }),
  }),
  ssrf: defineTool({
    id: "ssrf",
    displayName: "Server-side request forgery (SSRF)",
    category: "url",
    contextType: "field",
    description: "Detects URLs to internal addresses, internal names, wildcard DNS services and dangerous schemes.",
    config: noConfig(),
  }),
  url_length: defineTool({
    id: "url_length",
    displayName: "URL length",
    category: "url",
    contextType: "full",
    description: "Rejects URLs whose path, path segment, query or total length exceeds a limit.",
    config: z.strictObject({
      maxPathLength: positiveCount(1_048_576).default(2048),
      maxSegmentLength: positiveCount(1_048_576).default(255),
      maxQueryLength: positiveCount(1_048_576).default(4096),
      maxUrlLength: positiveCount(1_048_576).default(8192),
    }),
  }),
  url_parser_differential: defineTool({
    id: "url_parser_differential",
    displayName: "URL parser differential",
    category: "url",
    contextType: "field",
    description: "Detects URLs that different parsers resolve to different hosts.",
    config: noConfig(),
  }),
  url_validator: defineTool({
    id: "url_validator",
    displayName: "URL validator",
    category: "url",
    contextType: "field",
    description: "Rejects URL fields that are malformed, too long, use a disallowed scheme or embed credentials.",
    config: z.strictObject({
      maxLength: positiveCount(1_048_576).default(2048),
      allowedSchemes: list(z.string().regex(/^[a-z][a-z0-9+.-]*$/, "lowercase scheme"), 20).min(1).default(["http", "https"]).describe("Lowercase schemes without \":\"."),
      urlTypes: list(name(32), 20).default(["url", "uri"]).describe("Declared field types the tool validates; empty validates every string field the step targets."),
    }),
  }),
  web_cache_deception: defineTool({
    id: "web_cache_deception",
    displayName: "Web cache deception",
    category: "url",
    contextType: "full",
    description: "Flags requests for personal pages disguised with a static file extension a CDN would cache.",
    config: z.strictObject({
      staticPrefixes: list(z.string().regex(/^\/[^?#\s]*$/), 200).default([
        "/static/", "/assets/", "/public/", "/_next/static/", "/build/", "/dist/", "/images/", "/img/", "/css/", "/js/", "/fonts/",
      ]).describe("Lowercase path prefixes where real static files live; a static extension anywhere else is a disguise."),
    }),
  }),
} as const;
