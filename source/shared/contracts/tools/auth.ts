import { z } from "zod";
import {
  cidr, defineTool, durationMs, escalation, fieldNames, geoIpTable, headerName, headerNames, hostnames, list, name, names, origins, positiveCount, routeFilter, routes,
} from "./common";

const HOUR_MS = 3_600_000;

const ASYMMETRIC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"] as const;
const jwtAlgorithm = () => z.string().regex(/^[A-Za-z0-9+_-]{2,20}$/, "JWS algorithm name");

const placeholderValues = () => list(name(64), 100);

const loginRoutes = () => routeFilter().describe("Login endpoints. Omitted, every endpoint the step is attached to is a login endpoint.");

export const authTools = {
  account_enumeration: defineTool({
    id: "account_enumeration",
    displayName: "Account enumeration",
    category: "auth",
    contextType: "full",
    description: "Flags, then rejects, one client probing many identities on login, sign-up or password-reset routes.",
    config: z.strictObject({
      routes: routeFilter().describe("Routes that answer differently for existing and unknown accounts. Omitted, every attached endpoint."),
      windowMs: durationMs().default(600_000),
      identities: escalation({ suspicious: 15, block: 60 }, 10_000).describe("Distinct identities one client may probe in the window."),
    }),
  }),
  basic_auth_anomaly: defineTool({
    id: "basic_auth_anomaly",
    displayName: "Authorization header anomaly",
    category: "auth",
    contextType: "full",
    description: "Rejects malformed Authorization headers and Basic auth outside the routes that allow it; flags unknown schemes.",
    config: z.strictObject({
      basicAuthRoutes: routes().default([]).describe("Routes that accept HTTP Basic authentication; it is rejected everywhere else."),
    }),
  }),
  brute_force: defineTool({
    id: "brute_force",
    displayName: "Brute force",
    category: "auth",
    contextType: "full",
    description: "Flags, then rejects, repeated login attempts against one account.",
    config: z.strictObject({
      routes: loginRoutes(),
      windowMs: durationMs().default(900_000),
      attempts: escalation({ suspicious: 10, block: 30 }, 10_000).describe("Login attempts per account in the window."),
    }),
  }),
  cookie_abuse: defineTool({
    id: "cookie_abuse",
    displayName: "Cookie abuse",
    category: "auth",
    contextType: "full",
    description: "Rejects oversized Cookie headers, too many cookies or oversized values; flags malformed and duplicate cookies.",
    config: z.strictObject({
      maxHeaderBytes: positiveCount(1_048_576).default(4096),
      maxCookieCount: positiveCount(10_000).default(50),
      maxCookieValueBytes: positiveCount(1_048_576).default(4096),
    }),
  }),
  cookie_tampering: defineTool({
    id: "cookie_tampering",
    displayName: "Cookie tampering",
    category: "auth",
    contextType: "full",
    description: "Rejects signed cookies (express cookie-signature format) whose HMAC does not verify; flags unsigned and duplicate ones.",
    config: z.strictObject({
      secret: z.string().min(16).max(1024).describe("HMAC-SHA256 key the application signs cookies with. Distributed inside the signed bundle."),
      signedCookies: list(name(256).regex(/^[^A-Z]+$/, "lowercase cookie name"), 100).min(1).describe("Lowercase names of the cookies the application signs."),
      maxCookieValueBytes: positiveCount(1_048_576).default(4096),
    }),
  }),
  credential_stuffing: defineTool({
    id: "credential_stuffing",
    displayName: "Credential stuffing",
    category: "auth",
    contextType: "full",
    description: "Flags, then rejects, one source (IP, client fingerprint or network) trying many accounts on login.",
    config: z.strictObject({
      routes: loginRoutes(),
      windowMs: durationMs().default(600_000),
      limits: z.strictObject({
        ip: z.strictObject({ suspicious: positiveCount(), block: positiveCount().optional() }).default({ suspicious: 10, block: 50 }),
        fingerprint: z.strictObject({ suspicious: positiveCount(), block: positiveCount().optional() }).default({ suspicious: 30 })
          .describe("User-Agent + Accept-Language + Accept-Encoding: shared by many real users, so suspicious only by default."),
        asn: z.strictObject({ suspicious: positiveCount(), block: positiveCount().optional() }).default({ suspicious: 100 })
          .describe("Shared by everyone behind a carrier or cloud provider, so suspicious only by default."),
      }).prefault({}).describe("Distinct accounts per source in the window. A source without `block` is only ever suspicious."),
      asnTable: list(z.strictObject({ cidr: cidr(), asn: z.number().int().min(0).max(4_294_967_295) }), 100_000).default([]).describe("Network ownership used for the per-ASN count; without entries that count is skipped."),
    }),
  }),
  credentials_in_url: defineTool({
    id: "credentials_in_url",
    displayName: "Credentials in URL",
    category: "auth",
    contextType: "full",
    description: "Rejects passwords, API keys and tokens sent in the query string or as URL userinfo.",
    config: z.strictObject({
      secretParameters: fieldNames().default([
        "password", "passwd", "pwd", "pass", "apikey", "apisecret", "accesstoken", "authtoken", "secret", "clientsecret",
        "privatekey", "sessionid", "sessiontoken", "awssecretaccesskey", "jwt", "bearer",
      ]).describe("Query parameters that carry credentials. A generic \"token\" is left out: reset links legitimately use it."),
    }),
  }),
  cross_tenant_violation: defineTool({
    id: "cross_tenant_violation",
    displayName: "Cross-tenant violation",
    category: "auth",
    contextType: "full",
    description: "Rejects requests whose tenant header does not match the tenant claim of their bearer JWT.",
    config: z.strictObject({
      tenantHeader: headerName().default("x-tenant-id"),
      tenantClaims: names(20).min(1).default(["tenant_id", "tenantId", "tid", "tenant"]),
    }),
  }),
  csrf: defineTool({
    id: "csrf",
    displayName: "Cross-site request forgery (CSRF)",
    category: "auth",
    contextType: "full",
    description: "Rejects cookie-authenticated state changes that are cross-site, from a foreign origin, or lack a matching CSRF token.",
    config: z.strictObject({
      allowedOrigins: origins().min(1).describe("Origins of the application's own pages."),
      tokenHeaders: headerNames().default(["x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken"]),
      tokenFields: fieldNames().default(["csrf", "csrftoken", "xsrftoken", "authenticitytoken", "csrfmiddlewaretoken"]),
      tokenCookies: list(name(256), 50).default(["xsrf-token", "csrftoken", "csrf-token", "_csrf"]).describe("Lowercase cookies holding the double-submit token."),
    }),
  }),
  forced_browsing: defineTool({
    id: "forced_browsing",
    displayName: "Forced browsing",
    category: "auth",
    contextType: "full",
    description: "Rejects unauthenticated requests to privileged routes; flags JWTs on them that name no privileged role.",
    config: z.strictObject({
      routes: routeFilter().describe("Privileged routes. Omitted, every endpoint the step is attached to is privileged."),
      privilegedRoles: list(name(128), 200).min(1).default(["admin", "administrator", "superuser", "root", "staff", "ops", "support"]).describe("Lowercase roles, without a \"role_\" prefix, that may use privileged routes."),
    }),
  }),
  impossible_travel: defineTool({
    id: "impossible_travel",
    displayName: "Impossible travel",
    category: "auth",
    contextType: "full",
    description: "Flags one account seen from two places further apart than anyone can travel in the time between.",
    config: z.strictObject({
      geoIp: geoIpTable().min(1).describe("Geo-IP database: the location of each network."),
      maxSpeedKmh: positiveCount(100_000).default(1000).describe("Faster than a passenger jet."),
      minDistanceKm: z.number().int().min(0).max(20_100).default(500).describe("Nearby jumps are usually geo-IP noise."),
      memoryMs: durationMs().default(24 * HOUR_MS).describe("How long an account's last location is remembered."),
    }),
  }),
  invalid_bearer: defineTool({
    id: "invalid_bearer",
    displayName: "Invalid bearer token",
    category: "auth",
    contextType: "full",
    description: "Rejects malformed, placeholder, expired or not-yet-valid bearer tokens; flags unexpected JWT algorithms and key references.",
    config: z.strictObject({
      maxTokenLength: positiveCount(65_536).default(4096),
      clockSkewSeconds: z.number().int().min(0).max(3600).default(60),
      allowedAlgorithms: list(jwtAlgorithm(), 20).min(1).default([...ASYMMETRIC_ALGORITHMS, "EdDSA", "HS256"]),
    }),
  }),
  jwt_header_abuse: defineTool({
    id: "jwt_header_abuse",
    displayName: "JWT header abuse",
    category: "auth",
    contextType: "full",
    description: "Flags JWT headers built to attack the verifier: alg none or confusion, embedded or remote keys, kid injection, PBES2 abuse.",
    config: z.strictObject({
      allowedAlgorithms: list(jwtAlgorithm(), 20).min(1).default([...ASYMMETRIC_ALGORITHMS]),
      allowedTypes: list(name(64), 20).default(["jwt", "at+jwt", "jose"]).describe("Lowercase \"typ\" values."),
      maxTokenLength: positiveCount(65_536).default(4096),
      maxHeaderLength: positiveCount(65_536).default(1024).describe("Base64url characters; real headers are usually under 200."),
      maxKidLength: positiveCount(4096).default(256),
      maxPbes2Iterations: positiveCount(100_000_000).default(1_000_000),
    }),
  }),
  jwt_header_attacks: defineTool({
    id: "jwt_header_attacks",
    displayName: "JWT header attacks",
    category: "auth",
    contextType: "full",
    description: "Rejects JWTs (bearer, cookies, fields) with alg none, algorithm confusion, kid injection, untrusted or embedded keys.",
    config: z.strictObject({
      allowedAlgorithms: list(jwtAlgorithm(), 20).min(1).default(["RS256", "ES256"]).describe("The algorithms the issuer signs with; anything else, HS256 included, is a confusion attempt."),
      trustedKeyHosts: hostnames().default([]).describe("Hosts a token may point to with jku/x5u."),
      knownCritical: names(50).default(["b64", "exp"]).describe("\"crit\" extensions the verifier understands."),
    }),
  }),
  jwt_validation: defineTool({
    id: "jwt_validation",
    displayName: "JWT validation",
    category: "auth",
    contextType: "full",
    description: "Verifies bearer JWT signatures, issuer, audience and expiry against the issuer's public key.",
    config: z.strictObject({
      publicKey: z.string().max(16_384).regex(/^-----BEGIN [A-Z ]+-----/, "PEM public key or certificate").describe("PEM public key or certificate of the token issuer."),
      issuer: z.string().min(1).max(2048).optional().describe("Expected \"iss\"; omitted, any issuer is accepted."),
      audience: z.string().min(1).max(2048).optional().describe("Expected \"aud\"; omitted, any audience is accepted."),
      clockToleranceSeconds: z.number().int().min(0).max(3600).default(60),
      maxTokenLength: positiveCount(65_536).default(4096),
      allowedAlgorithms: list(z.enum(ASYMMETRIC_ALGORITHMS), 9).min(1).default([...ASYMMETRIC_ALGORITHMS]).describe("Asymmetric only: HS* next to a public key lets anyone sign with the public key as the secret."),
    }),
  }),
  missing_authentication: defineTool({
    id: "missing_authentication",
    displayName: "Missing authentication",
    category: "auth",
    contextType: "full",
    description: "Rejects requests that carry no usable credential (header, API key or session cookie) outside public endpoints.",
    config: z.strictObject({
      publicEndpoints: list(z.string().max(1024).regex(/^\/[^?#\s*]*(?:\/\*)?$/, "path, optionally ending in /*"), 500).default([]).describe("Paths callable without credentials; \"/docs/*\" covers \"/docs\" and below. Attach the tool to protected endpoints only and leave this empty."),
      credentialHeaders: headerNames().default(["x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-session-token", "x-token"]).describe("Lowercase headers that carry a credential on their own."),
      credentialCookies: fieldNames().default([
        "session", "sessionid", "sessid", "sid", "jsessionid", "phpsessid", "connectsid", "laravelsession",
        "token", "accesstoken", "authtoken", "idtoken", "jwt", "auth", "authorization",
      ]).describe("Session cookie names, lowercased without a __Host-/__Secure- prefix and without \"_\", \"-\" and \".\"."),
      placeholders: placeholderValues().default(["null", "undefined", "nan", "none", "false", "true", "bearer", "token", "[object object]"]).describe("Values clients send when a variable was never set (\"Bearer undefined\")."),
    }),
  }),
  oauth_flow_validation: defineTool({
    id: "oauth_flow_validation",
    displayName: "OAuth flow validation",
    category: "auth",
    contextType: "full",
    description: "Rejects authorization requests with unregistered redirect URIs, weak state or missing PKCE, and callbacks reusing a state.",
    config: z.strictObject({
      authorizeRoutes: routes().default([]),
      callbackRoutes: routes().default([]),
      redirectUris: list(z.url().max(2048), 100).default([]).describe("redirect_uri values registered for the client, matched exactly."),
      stateMemoryMs: durationMs().default(900_000).describe("Longer than any authorization round trip."),
      minStateLength: positiveCount(256).default(8),
      requirePkce: z.boolean().default(true),
    }).refine((value) => value.authorizeRoutes.length + value.callbackRoutes.length > 0, "set authorizeRoutes, callbackRoutes or both"),
  }),
  otp_brute_force: defineTool({
    id: "otp_brute_force",
    displayName: "OTP brute force",
    category: "auth",
    contextType: "full",
    description: "Rejects guessing one-time codes: too many distinct codes per account or per client.",
    config: z.strictObject({
      routes: routeFilter().describe("Code verification endpoints. Omitted, every endpoint the step is attached to."),
      windowMs: durationMs().default(600_000),
      maxGuessesPerAccount: positiveCount(10_000).default(5).describe("A 6-digit code survives 5 guesses with 99.9995% probability."),
      maxGuessesPerClient: positiveCount(10_000).default(20).describe("The same client spreading guesses over several accounts."),
      codeFields: fieldNames().min(1).default(["code", "otp", "totp", "mfacode", "token", "verificationcode", "resetcode", "pin"]),
    }),
  }),
  password_spraying: defineTool({
    id: "password_spraying",
    displayName: "Password spraying",
    category: "auth",
    contextType: "full",
    description: "Flags one password tried against many accounts, or one client trying many accounts with few passwords.",
    config: z.strictObject({
      routes: loginRoutes(),
      windowMs: durationMs().default(1_800_000),
      accountsPerPassword: positiveCount(100_000).default(10).describe("One password tried against this many accounts, from anywhere."),
      accountsPerClient: positiveCount(100_000).default(10).describe("One client trying this many accounts..."),
      passwordsPerClient: positiveCount(1000).default(3).describe("...with at most this many different passwords."),
      passwordFields: fieldNames().min(1).default(["password", "passwd", "pass", "pwd"]),
    }),
  }),
  session_binding: defineTool({
    id: "session_binding",
    displayName: "Session binding",
    category: "auth",
    contextType: "full",
    description: "Flags a session that moves to another network, User-Agent or platform.",
    config: z.strictObject({
      sessionTtlMs: durationMs().default(12 * HOUR_MS).describe("How long a session's binding is remembered."),
    }),
  }),
  session_fixation: defineTool({
    id: "session_fixation",
    displayName: "Session fixation",
    category: "auth",
    contextType: "full",
    description: "Flags session IDs supplied in the path, query or body, cookie planting payloads, and weak or duplicate session cookies.",
    config: z.strictObject({
      sessionNames: fieldNames().default([
        "sessionid", "sessid", "sid", "session", "sessionkey", "sessiontoken", "phpsessid", "jsessionid",
        "aspnetsessionid", "connectsid", "laravelsession", "cfid", "cftoken",
      ]).describe("Session parameter names, lowercased without \"_\", \"-\", \".\" and spaces. \"aspsessionid*\" is always matched by prefix."),
      minSessionIdLength: positiveCount(512).default(16),
      minDistinctChars: positiveCount(64).default(6),
      maxSessionIdLength: positiveCount(16_384).default(512),
    }).refine((value) => value.minSessionIdLength <= value.maxSessionIdLength, "minSessionIdLength must not exceed maxSessionIdLength"),
  }),
  token_replay: defineTool({
    id: "token_replay",
    displayName: "Single-use token replay",
    category: "auth",
    contextType: "full",
    description: "Flags a single-use token (reset link, magic link, verification code) used more than once.",
    config: z.strictObject({
      routes: routeFilter().describe("Routes that consume single-use tokens. Omitted, every endpoint the step is attached to."),
      memoryMs: durationMs().default(24 * HOUR_MS).describe("Longer than any reset link or magic link stays valid."),
      tokenFields: fieldNames().min(1).default(["token", "code", "resettoken", "magictoken", "verificationtoken", "confirmationtoken", "otp"]),
      minTokenLength: positiveCount(1024).default(6),
    }),
  }),
} as const;
