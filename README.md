# Tessera proxy

The proxy enforces a signed tenant policy from the Tessera dashboard. It pulls
the active bundle at startup, verifies its Ed25519 signature and content hash,
then keeps that immutable snapshot until restart. It writes a verified local
copy for dashboard outages. A first start without a valid bundle exits before
opening the ingress port ([ADR-0001](docs/adr/0001-first-start-without-bundle.md)).

## Configuration

Copy `.env.example` to `.env` and set:

- `TENANT_ID`: the 24-character MongoDB ObjectId issued by the dashboard;
- `DASHBOARD_API_URL`: dashboard API origin, with a trailing slash if it has a
  base path;
- `DEPLOYMENT_API_KEY`: deployment key with `bundles:read`,
  `jev-credentials:read`, `heartbeats:write` and `telemetry:write` scopes;
- `BUNDLE_PUBLIC_KEY`: trusted Ed25519 public key in PEM form. Literal `\n`
  separators are accepted;
- `BUNDLE_CACHE_FILE`: writable location for the verified bundle;
- `REDIS_URL`: runtime cache connection address; Redis failure does not stop
  enforcement;
- `PORT`: ingress port (default `62197`).

Run `npm install` and `npm run dev`. Activate a `tessera.bundle/v2` policy in
the dashboard before the first proxy start. A previously activated v1 bundle
must be reactivated with explicit decision settings to produce v2.

The v2 runtime configuration carries sampling bounds, JEV threshold and floor,
and separate behaviors for static-analysis errors and unavailable JEV. Field
targets use `body.<field>` or `query.<field>`; file targets name the upload field. Policy endpoint keys use
`METHOD /path`; `:name` matches exactly one nonempty path segment. The
`routing.pathPrefix` is removed before policy matching and upstream forwarding.
Paths are matched without decoding, and a trailing slash is significant.
The supported tools and their configuration contracts are described in
[docs/tool-registry-inventory.md](docs/tool-registry-inventory.md) and listed in
[docs/tool-registry.json](docs/tool-registry.json).
The versioned network schemas live in [source/shared/contracts](source/shared/contracts).

The proxy checks for a newer bundle once per minute and reports that a restart
is needed. It never changes the active policy while handling requests. It also
refreshes the organization JEV credential once per minute and sends a heartbeat
and redacted minute counters to the dashboard. Request content and secrets are
not included in telemetry.
