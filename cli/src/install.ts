import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";

/*
 * `tessera --install`: everything outside node_modules that Tessera needs. The npm packages themselves are
 * installed by bin/tessera.js before this file can even load (it needs tsx, commander and zod).
 */

export type PackageManager = "apt" | "dnf" | "brew";

export interface Host {
  platform: NodeJS.Platform;
  arch: string;
  isRoot: boolean;
  packageManager?: PackageManager;
  /** Where binaries without a package go; added to PATH for the rest of the install. */
  binDir: string;
  has(binary: string): boolean;
}

export type Step = (
  | { kind: "command"; command: string[] }
  | { kind: "release"; repo: string; binary: string }
  | { kind: "manual" }
) & {
  title: string;
  /** Binary that must exist before this step can run; when an earlier step failed to provide it, the step is skipped. */
  needs?: string;
};

/** Binaries the environment analyzer runs, plus Redis for the proxy's storage. */
export const REQUIRED_BINARIES = ["nmap", "nuclei", "trivy", "httpx", "lynis", "redis-server"] as const;

/** Binary checked → package that provides it. curl and unzip are needed by the steps below, not by Tessera. */
const PACKAGES: Record<PackageManager, Record<string, string>> = {
  apt: { nmap: "nmap", lynis: "lynis", "redis-server": "redis-server", curl: "curl", unzip: "unzip" },
  dnf: { nmap: "nmap", lynis: "lynis", "redis-server": "redis", curl: "curl", unzip: "unzip" },
  brew: { nmap: "nmap", lynis: "lynis", "redis-server": "redis", nuclei: "nuclei", httpx: "httpx", trivy: "trivy" },
};

const PROJECTDISCOVERY = { nuclei: "projectdiscovery/nuclei", httpx: "projectdiscovery/httpx" } as const;

const TRIVY_SCRIPT = "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh";

export function planInstall(host: Host): Step[] {
  const steps: Step[] = [];
  const packages = host.packageManager ? PACKAGES[host.packageManager] : {};
  const sudo = host.isRoot || host.packageManager === "brew" ? [] : ["sudo"];

  const missingPackages = Object.entries(packages)
    .filter(([binary]) => !host.has(binary))
    .map(([, name]) => name);
  if (missingPackages.length > 0) {
    const title = `Install ${missingPackages.join(", ")}`;
    if (host.packageManager === "apt") {
      steps.push({ kind: "command", title: "Refresh apt package lists", command: [...sudo, "apt-get", "update"] });
      steps.push({ kind: "command", title, command: [...sudo, "apt-get", "install", "-y", ...missingPackages] });
    } else if (host.packageManager === "dnf") {
      steps.push({ kind: "command", title, command: [...sudo, "dnf", "install", "-y", ...missingPackages] });
    } else {
      steps.push({ kind: "command", title, command: ["brew", "install", ...missingPackages] });
    }
  }

  const unpackaged = (binary: string) => !(binary in packages) && !host.has(binary);
  for (const binary of ["nmap", "lynis", "redis-server"]) {
    if (unpackaged(binary)) steps.push({ kind: "manual", title: `Install ${binary} with your system package manager` });
  }
  if (unpackaged("trivy")) {
    steps.push({
      kind: "command",
      title: "Install trivy",
      command: ["sh", "-c", `curl -sfL ${TRIVY_SCRIPT} | sh -s -- -b "${host.binDir}"`],
      needs: "curl",
    });
  }
  for (const binary of ["nuclei", "httpx"] as const) {
    if (unpackaged(binary)) {
      steps.push({ kind: "release", title: `Install ${binary}`, repo: PROJECTDISCOVERY[binary], binary, needs: "unzip" });
    }
  }

  // Without templates nuclei downloads them during the first scan and blows through its timeout.
  steps.push({ kind: "command", title: "Update nuclei templates", command: ["nuclei", "-update-templates"], needs: "nuclei" });
  return steps;
}

function onPath(binary: string): boolean {
  return (process.env["PATH"] ?? "").split(delimiter).some((dir) => dir && existsSync(join(dir, binary)));
}

function detectHost(binDir: string): Host {
  const packageManager = (["brew", "apt", "dnf"] as const).find((manager) => onPath(manager === "apt" ? "apt-get" : manager));
  return {
    platform: process.platform,
    arch: process.arch,
    isRoot: process.getuid?.() === 0,
    packageManager,
    binDir,
    has: (binary) =>
      // Python's httpx ships an `httpx` command too; only ProjectDiscovery's understands -version.
      binary === "httpx" ? spawnSync("httpx", ["-version"], { stdio: "ignore" }).status === 0 : onPath(binary),
  };
}

function runCommand([command, ...args]: string[]): void {
  const result = spawnSync(command!, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with ${result.status ?? result.signal}`);
}

/** Reads a download, printing every 10% so a large binary on a slow link does not look like a hang. */
async function readWithProgress(response: Response, name: string): Promise<Buffer> {
  const total = Number(response.headers.get("content-length")) || 0;
  const chunks: Uint8Array[] = [];
  let received = 0;
  let reported = 0;
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    chunks.push(chunk);
    received += chunk.length;
    const percent = total ? Math.floor((received / total) * 10) * 10 : 0;
    if (percent > reported) {
      reported = percent;
      console.error(`      ${name}: ${percent}% of ${(total / 1024 / 1024).toFixed(0)} MB`);
    }
  }
  return Buffer.concat(chunks);
}

/** Downloads a ProjectDiscovery release zip and unpacks its binary into binDir. */
async function installRelease(repo: string, binary: string, host: Host): Promise<void> {
  const os = host.platform === "darwin" ? "macOS" : host.platform;
  const arch = { x64: "amd64", arm64: "arm64", ia32: "386" }[host.arch] ?? host.arch;
  // github.com redirects /releases/latest to /releases/tag/<tag>; unlike api.github.com it has no 60 requests/hour limit.
  const latest = await fetch(`https://github.com/${repo}/releases/latest`, { method: "HEAD" });
  const tag = latest.url.split("/releases/tag/")[1];
  if (!latest.ok || !tag) throw new Error(`could not find the latest ${repo} release (GitHub answered ${latest.status})`);
  const asset = `${binary}_${tag.replace(/^v/, "")}_${os}_${arch}.zip`;

  const download = await fetch(`https://github.com/${repo}/releases/download/${tag}/${asset}`);
  if (!download.ok) throw new Error(`download of ${asset} failed with ${download.status}`);
  const dir = mkdtempSync(join(tmpdir(), "tessera-install-"));
  try {
    const zip = join(dir, asset);
    writeFileSync(zip, await readWithProgress(download, asset));
    runCommand(["unzip", "-o", "-q", zip, binary, "-d", host.binDir]);
    chmodSync(join(host.binDir, binary), 0o755);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Copies .env.example so the proxy and the CLI start with every setting named, if not yet valued. */
function ensureEnvFile(repoRoot: string): void {
  const envFile = resolve(repoRoot, ".env");
  const example = resolve(repoRoot, ".env.example");
  if (existsSync(envFile) || !existsSync(example)) return;
  copyFileSync(example, envFile);
  console.error("\nCreated .env from .env.example");
}

const say = (message = ""): void => console.error(message);

/** What each tool is for, so the report explains why it is being installed. */
const PURPOSE: Record<(typeof REQUIRED_BINARIES)[number], string> = {
  nmap: "port and service scan",
  nuclei: "vulnerability templates scan",
  trivy: "project dependency scan",
  httpx: "HTTP fingerprinting",
  lynis: "host hardening audit",
  "redis-server": "proxy storage and cache",
};

function describeCommand(step: Extract<Step, { kind: "command" }>): string {
  return step.command.map((part) => (/\s/.test(part) ? JSON.stringify(part) : part)).join(" ");
}

function seconds(startedAt: number): string {
  return `${((Date.now() - startedAt) / 1000).toFixed(1)}s`;
}

export async function runInstall(repoRoot: string): Promise<void> {
  if (process.platform !== "linux" && process.platform !== "darwin") {
    throw new Error(`--install supports Linux and macOS, not ${process.platform}`);
  }
  const binDir = join(homedir(), ".local", "bin");
  mkdirSync(binDir, { recursive: true });
  const binDirOnPath = (process.env["PATH"] ?? "").split(delimiter).includes(binDir);
  process.env["PATH"] = `${binDir}${delimiter}${process.env["PATH"] ?? ""}`;

  const host = detectHost(binDir);
  say(`Tessera: installing dependencies on ${host.platform}/${host.arch} (${host.packageManager ?? "no supported package manager"}${host.isRoot ? ", root" : ""})`);
  say("\nTools Tessera needs:");
  const before = new Set(REQUIRED_BINARIES.filter((binary) => host.has(binary)));
  for (const binary of REQUIRED_BINARIES) {
    say(`  ${before.has(binary) ? "found  " : "missing"}  ${binary.padEnd(13)} ${PURPOSE[binary]}`);
  }

  ensureEnvFile(repoRoot);

  const steps = planInstall(host);
  say(`\n${steps.length} step${steps.length === 1 ? "" : "s"} to run${host.isRoot || host.packageManager === "brew" ? "" : "; system packages use sudo and may ask for your password"}.`);
  const failed: string[] = [];
  const startedAll = Date.now();
  for (const [index, step] of steps.entries()) {
    const label = `[${index + 1}/${steps.length}]`;
    say(`\n${label} ${step.title}`);
    if (step.kind === "command") say(`      $ ${describeCommand(step)}`);
    if (step.kind === "release") say(`      downloading the latest ${step.repo} release into ${binDir}`);
    const startedAt = Date.now();
    if (step.needs && !host.has(step.needs)) {
      say(`${label} SKIPPED: needs ${step.needs}, which an earlier step did not install`);
      failed.push(step.title);
      continue;
    }
    try {
      if (step.kind === "manual") throw new Error("no supported package manager (apt, dnf or brew) found");
      if (step.kind === "command") runCommand(step.command);
      else await installRelease(step.repo, step.binary, host);
      say(`${label} done in ${seconds(startedAt)}`);
    } catch (error) {
      say(`${label} FAILED after ${seconds(startedAt)}: ${error instanceof Error ? error.message : error}`);
      failed.push(step.title);
    }
  }

  say(`\nSummary (${seconds(startedAll)}):`);
  const missing: string[] = [];
  for (const binary of REQUIRED_BINARIES) {
    const ok = host.has(binary);
    if (!ok) missing.push(binary);
    const state = ok ? (before.has(binary) ? "already installed" : "installed now") : "STILL MISSING";
    say(`  ${ok ? "ok    " : "FAILED"}  ${binary.padEnd(13)} ${state}`);
  }
  const redisUp = spawnSync("redis-cli", ["ping"], { encoding: "utf8" }).stdout?.trim() === "PONG";
  say(`  ${redisUp ? "ok    " : "WARN  "}  ${"redis".padEnd(13)} ${redisUp ? "answering on PING" : "not running"}`);

  say("\nNext:");
  if (!binDirOnPath) say(`  - add ${binDir} to your PATH, tools were installed there`);
  if (!redisUp) {
    say(`  - start Redis: ${host.packageManager === "brew" ? "brew services start redis" : "sudo systemctl enable --now redis-server"}`);
  }
  say("  - fill in TENANT_ID, DEPLOYMENT_API_KEY and TESSERA_API_KEY in .env");
  say("  - run: tessera --analyze-env");

  if (failed.length > 0 || missing.length > 0) {
    say(`\nTessera: install incomplete${missing.length > 0 ? `, still missing ${missing.join(", ")}` : ""}`);
    process.exitCode = 1;
    return;
  }
  say("\nTessera: every dependency is installed");
}
