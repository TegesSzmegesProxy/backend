# Tessera proxy

The proxy enforces a signed tenant policy from the Tessera dashboard. Policies
reach it only through `tessera fetch`
([ADR-0002](docs/adr/0002-policies-fetched-into-redis.md)):
1. The fetch pulls the active bundle.
2. It verifies the bundle's Ed25519 signature, content hash, tenant and every
   tool step, and builds every tool.
3. It stores the signed bundle in Redis.

At startup, Ingress loads the stored bundle and verifies it again. If Redis is
unreachable, nothing was fetched, or the stored bundle is invalid, the proxy
exits before opening the ingress port and asks you to run `tessera fetch`.

## Configuration

Copy `.env.example` to `.env` and set:

- `TENANT_ID`: the 24-character MongoDB ObjectId issued by the dashboard;
- `DASHBOARD_API_URL`: dashboard API origin, with a trailing slash if it has a
  base path;
- `DEPLOYMENT_API_KEY`: deployment key with `bundles:read`,
  `jev-credentials:read`, `heartbeats:write` and `telemetry:write` scopes;
- `BUNDLE_PUBLIC_KEY`: trusted Ed25519 public key in PEM form. Literal `\n`
  separators are accepted;
- `REDIS_URL`: Redis address. It holds the fetched policies and the state of
  tools that look across requests. The proxy cannot start without it; an outage
  while running keeps the loaded policy;
- `PORT`: ingress port (default `62197`).

Run `npm install`, activate a policy in the dashboard, then:

```sh
node cli/bin/tessera.js fetch      # the `tessera` binary of cli/ (npm --prefix cli link installs it)
npm run dev
```

`tessera fetch` reads the same `.env` settings. It prints the stored version and
its steps per scope, and reports when Redis already holds the active version
(`--force` stores it again, e.g. to repair a damaged copy). If any check fails,
Redis keeps the policies it had.

Analyses produce `tessera.policy/v3` policies, distributed as
`tessera.bundle/v3`:
- global and environment steps run on every request, including unlisted
  endpoints when unknown endpoints are allowed;
- endpoint steps run on their endpoint;
- when a tool and target appear in more than one scope, the endpoint step wins,
  then the environment one;
- JEV receives the policy's description of legitimate traffic as labelled
  data.

`tessera.bundle/v2` (endpoint steps only) is still accepted.

The v2 runtime configuration carries sampling bounds, JEV threshold and floor,
and separate behaviors for static-analysis errors and unavailable JEV. Field
targets use `body.<field>` or `query.<field>`, with `[]` matching any array index
(`body.items[].sku`); global and environment steps may also use `body.*`,
`query.*` or `*`. File targets name the upload field. Policy endpoint keys use
`METHOD /path`; `:name` matches exactly one nonempty path segment. The
`routing.pathPrefix` is removed before policy matching and upstream forwarding.
Paths are matched without decoding, and a trailing slash is significant.
The supported tools and their configuration contracts are described in
[docs/tool-registry-inventory.md](docs/tool-registry-inventory.md) and listed in
[docs/tool-registry.json](docs/tool-registry.json).
The versioned network schemas live in [source/shared/contracts](source/shared/contracts).

A running proxy picks up a newly fetched bundle within 30 seconds. It is
announced over Redis, and the proxy also polls. Each request runs entirely on
one policy version.

A fetched bundle that changes the upstream is not applied until restart. Once a
minute the proxy asks the dashboard whether a newer bundle is active, and only
reports it. It also refreshes the organization JEV credential once per minute and sends a heartbeat
and redacted minute counters to the dashboard. Request content and secrets are
not included in telemetry.

## Tessera CLI

Put `cli/bin` on your PATH once, then run `tessera --install` to install every dependency (npm packages,
nmap, nuclei, httpx, trivy, lynis, Redis, `.env`). After that `tessera --analyze-env`, `tessera project <tenant>`
and the other options work from any directory. Replace the path below with where you cloned the repository.

Linux (bash: use `~/.bashrc` instead of `~/.zshrc`):

```sh
echo 'export PATH="$HOME/Tessera/cli/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

macOS (zsh is the default shell):

```sh
echo 'export PATH="$HOME/Tessera/cli/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

Windows:

Add `cli\bin` to your user `Path` in Environment Variables and open a new terminal.

Check it with `tessera --help`. `tessera --install` itself supports Linux (apt, dnf) and macOS (Homebrew); on
Windows it installs the npm packages and the scanners must be installed by hand.
