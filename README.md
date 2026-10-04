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

## Tessera CLI

`tessera` installs the proxy's dependencies and runs the scanners and the proxy for a tenant. Setup is three steps:
install Node.js, put the CLI on your PATH, run `tessera --install`.

### 1. Requirements

- **Node.js 20.12 or newer** (check with `node --version`) and npm. Get it from <https://nodejs.org>.
- **Git**, to clone the repository.
- A system package manager for `tessera --install` to use:

| OS      | Supported by `--install`        | Notes                                                              |
| ------- | ------------------------------- | ------------------------------------------------------------------ |
| macOS   | [Homebrew](https://brew.sh)     | No `sudo` needed.                                                  |
| Linux   | `apt` (Debian, Ubuntu) or `dnf` (Fedora, RHEL) | Asks for your `sudo` password. nuclei, httpx and trivy are downloaded separately. |
| Windows | npm packages only               | Install nmap, nuclei, httpx, trivy, lynis and Redis yourself (or use WSL2 and follow the Linux steps). |

### 2. Put the CLI on your PATH

Run these from the repository root (the folder that contains `cli/`). They use the current directory, so they work
wherever you cloned it. Do it once, then open a new terminal.

macOS (zsh):

```sh
cd /path/to/your/clone
echo "export PATH=\"$PWD/cli/bin:\$PATH\"" >> ~/.zshrc && source ~/.zshrc
```

Linux (bash; for zsh use `~/.zshrc`):

```sh
cd /path/to/your/clone
echo "export PATH=\"$PWD/cli/bin:\$PATH\"" >> ~/.bashrc && source ~/.bashrc
```

Windows:

1. Press the Windows key, type `environment variables` and open **Edit environment variables for your account**.
2. Under **User variables**, select **Path** and click **Edit**.
3. Click **New** and paste the full path to the `cli\bin` folder inside your clone, for example
   `C:\Users\you\Tessera\cli\bin`. Click **OK** on every window.
4. Open a **new** terminal (PowerShell or cmd) so it picks up the change.

Re-running a command adds a duplicate PATH line; that is harmless, but you can delete the extra one from your shell
profile.

### 3. Install everything

```sh
tessera --install
```

This installs the npm packages (proxy and CLI), nmap, nuclei, httpx, trivy, lynis and Redis, and creates `.env` from
`.env.example`. Before `--install` has run, any other `tessera` command answers
`npm packages are not installed yet`; that is expected.

Then fill in `.env` (see [Configuration](#configuration)) and start Redis if the installer says it is not running:

```sh
brew services start redis                  # macOS
sudo systemctl enable --now redis-server   # Linux (the unit may be called redis on Fedora)
```

### 4. Use it

```sh
tessera --help                  # all options
tessera --analyze-env           # run the environment analyzer with every tool enabled
tessera project <tenant-id>     # run Tessera for a tenant
```

Useful `--analyze-env` options: `--target <url|host|ip>` (repeatable), `--project-path <dir>`,
`--output <file>`, `--no-send`, `--disable-<tool>`.

### Troubleshooting

- **`command not found: tessera`**: open a new terminal, or check that `<clone>/cli/bin` appears in `echo $PATH`
  (`echo %PATH%` in cmd). On Linux/macOS also check `chmod +x cli/bin/tessera`.
- **`Node.js 20.12 or newer is required`**: upgrade Node.js.
- **`command not found: compdef` or similar from your shell profile**: not Tessera. A completion line in your
  profile (for example `ng completion`) runs before zsh's completion system is loaded; put
  `autoload -Uz compinit && compinit` above it.
- **`--install` says no supported package manager**: install Homebrew (macOS) or use an apt/dnf distribution, or install
  the tools in the table above by hand; `tessera --install` will skip what is already on your PATH.
