import { z } from "zod";
import {
  cidr, cidrs, countryCodes, defineTool, durationMs, escalation, fieldNames, geoIpTable, headerNames, list, name, noConfig, positiveCount, ratio,
  route, routes,
} from "./common";

const ja3 = () => z.string().regex(/^[0-9a-f]{32}$/, "lowercase JA3 MD5 hash");
const ja3List = () => list(ja3(), 10_000).default([]);

export const botTools = {
  datacenter_asn: defineTool({
    id: "datacenter_asn",
    displayName: "Datacenter ASN",
    category: "bot",
    contextType: "full",
    description: "Flags clients connecting from hosting and cloud networks rather than homes and phones.",
    config: z.strictObject({
      asnTable: list(z.strictObject({
        cidr: cidr(),
        asn: z.number().int().min(0).max(4_294_967_295),
        org: z.string().max(200),
        hosting: z.boolean(),
      }), 100_000).min(1).describe("Network ownership; `hosting` marks datacenter and cloud networks."),
      serverToServerRoutes: routes().default([]).describe("Routes servers are expected to call (webhooks, metrics scrapers), where hosting traffic is normal."),
    }),
  }),
  geo_policy: defineTool({
    id: "geo_policy",
    displayName: "Geo policy",
    category: "bot",
    contextType: "full",
    description: "Rejects denied countries and countries a route does not allow; flags countries outside the expected set.",
    config: z.strictObject({
      geoIp: geoIpTable().min(1),
      deny: countryCodes().default([]).describe("Countries rejected everywhere."),
      expected: countryCodes().optional().describe("Countries normally seen; others are suspicious. Omitted, no country is unusual."),
      routes: list(z.strictObject({ route: route(), allow: countryCodes().min(1) }), 500).default([]).describe("Per-route allowlists; the most specific matching route wins."),
    }),
  }),
  header_order_fingerprint: defineTool({
    id: "header_order_fingerprint",
    displayName: "Header order fingerprint",
    category: "bot",
    contextType: "full",
    description: "Flags clients claiming to be a browser whose header order and set match an HTTP library instead.",
    config: noConfig(),
  }),
  headless_browser: defineTool({
    id: "headless_browser",
    displayName: "Headless browser",
    category: "bot",
    contextType: "full",
    description: "Flags automation markers in the User-Agent, client hints and headers, and automation reported by the page.",
    config: z.strictObject({
      clientSignalFields: fieldNames().default(["webdriver", "navigatorwebdriver", "headless", "automation"]).describe("Fields the application's client-side script fills when it detects automation (navigator.webdriver, ...)."),
    }),
  }),
  ip_reputation: defineTool({
    id: "ip_reputation",
    displayName: "IP reputation",
    category: "bot",
    contextType: "full",
    description: "Rejects or flags clients from networks a threat-intelligence feed scores as malicious.",
    config: z.strictObject({
      feed: list(z.strictObject({
        cidr: cidr(),
        score: z.number().int().min(0).max(100),
        lists: list(name(100), 50).default([]),
      }), 100_000).min(1).describe("Threat-intelligence feed; score 0-100."),
      blockScore: z.number().int().min(0).max(100).default(90),
      suspiciousScore: z.number().int().min(0).max(100).default(50),
    }).refine((value) => value.suspiciousScore <= value.blockScore, "suspiciousScore must not exceed blockScore"),
  }),
  not_found_spike: defineTool({
    id: "not_found_spike",
    displayName: "404/403 spike",
    category: "bot",
    contextType: "full",
    description: "Flags, then rejects, clients whose recent responses are mostly 404/403-style errors (enumeration).",
    config: z.strictObject({
      windowMs: durationMs().default(60_000),
      errors: escalation({ suspicious: 30, block: 100 }, 100_000).describe("Error responses per client in the window."),
      minErrorRatio: ratio().default(0.5).describe("A busy client with a few broken links is not enumerating."),
      errorStatuses: list(z.number().int().min(100).max(599), 50).min(1).default([404, 403, 401, 405]),
    }),
  }),
  scanner_signature: defineTool({
    id: "scanner_signature",
    displayName: "Scanner signature",
    category: "bot",
    contextType: "full",
    description: "Rejects requests from self-identifying security scanners; flags out-of-band callback domains in payloads.",
    config: noConfig(),
  }),
  sensitive_file_probe: defineTool({
    id: "sensitive_file_probe",
    displayName: "Sensitive file probe",
    category: "bot",
    contextType: "full",
    description: "Rejects requests for files no deployment should serve (.env, .git, backups, admin tooling, debug endpoints).",
    config: noConfig(),
  }),
  tls_fingerprint: defineTool({
    id: "tls_fingerprint",
    displayName: "TLS fingerprint",
    category: "bot",
    contextType: "full",
    description: "Flags clients whose TLS (JA3) fingerprint belongs to an HTTP library or another browser than the one claimed.",
    config: z.strictObject({
      browserJa3: z.strictObject({ chrome: ja3List(), firefox: ja3List(), safari: ja3List() }).prefault({}).describe("JA3 hashes per browser family."),
      libraryJa3: list(z.strictObject({ ja3: ja3(), library: name(100) }), 10_000).default([]).describe("JA3 hashes of HTTP libraries and tools."),
      trustedProxies: cidrs(1000).default([]).describe("TLS-terminating proxies whose fingerprint headers are trusted."),
      fingerprintHeaders: headerNames().default(["x-ja3-fingerprint", "x-ja3-hash", "cf-ja3-hash"]).describe("Headers those proxies pass the fingerprint in."),
    }),
  }),
  tor_exit_node: defineTool({
    id: "tor_exit_node",
    displayName: "Tor exit node",
    category: "bot",
    contextType: "full",
    description: "Flags clients connecting from a Tor exit node.",
    config: z.strictObject({
      exitNodes: list(z.string().regex(/^[0-9a-f:.]{2,45}$/, "IP address"), 100_000).min(1).describe("Exit node addresses, normalized (lowercase IPv6, plain IPv4)."),
    }),
  }),
  user_agent_anomaly: defineTool({
    id: "user_agent_anomaly",
    displayName: "User-Agent anomaly",
    category: "bot",
    contextType: "full",
    description: "Flags missing, malformed or outdated User-Agents and client hints that contradict them.",
    config: z.strictObject({
      minMajor: z.strictObject({
        chrome: positiveCount(1000).default(110),
        firefox: positiveCount(1000).default(110),
        safari: positiveCount(1000).default(14),
      }).prefault({}).describe("Majors older than these are years out of date; real users auto-update, old bot kits don't."),
      minLength: positiveCount(1000).default(10),
      maxLength: positiveCount(65_536).default(512),
    }).refine((value) => value.minLength <= value.maxLength, "minLength must not exceed maxLength"),
  }),
} as const;
