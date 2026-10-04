#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseEnv } from "node:util";
import { Command, InvalidArgumentError } from "commander";
import {
  InputError,
  parseApiUrl,
  parseDirectory,
  parseOutputFile,
  parsePort,
  parseProjectId,
  parseRateLimit,
  parseTargetList,
  parseTenant,
} from "./inputs";
import { runInstall } from "./install";
import { createProgress } from "./progress";
import { createPrompter } from "./prompt";
import { loadExpectedDurations, saveDurations } from "./timings";
import {
  EnvironmentAnalyzer,
  EnvironmentInputError,
  ExecFileRunner,
  type EnvironmentTool,
} from "../../source/core/environment-analysis";
import { BundleFetcher, BundleVerificationError, fetchPolicies, PolicySnapshot, PolicyStore } from "../../source/core/policy";
import { loadConfig } from "../../source/shared/config";
import { BundleVerifier } from "../../source/shared/contracts";
import { RedisStorage } from "../../source/shared/storage";

const repoRoot = resolve(__dirname, "..", "..");
const bootstrapPath = resolve(repoRoot, "source", "bootstrap.ts");

/** Adapts a validator to a commander option parser, which reports only InvalidArgumentError nicely. */
function asArgument<T>(parse: (value: string) => T): (value: string) => T {
  return (value) => {
    try {
      return parse(value);
    } catch (error) {
      if (error instanceof InputError) throw new InvalidArgumentError(error.message);
      throw error;
    }
  };
}

function collectTargets(value: string, previous: string[]): string[] {
  return [...previous, ...asArgument(parseTargetList)(value)];
}

function fail(message: string): never {
  console.error(`Tessera: ${message}`);
  process.exit(1);
}

/** Runs a validator on a value that did not come through commander (environment, .env, defaults). */
function checked<T>(source: string, parse: (value: string) => T, value: string): T {
  try {
    return parse(value);
  } catch (error) {
    if (error instanceof InputError) fail(`${source}: ${error.message}`);
    throw error;
  }
}

/** The proxy's TENANT_ID: the project's id in the control plane. */
function parseProxyTenant(value: string): string {
  if (!/^[a-f0-9]{24}$/.test(value)) {
    throw new InvalidArgumentError("must be the project's 24-character lowercase hex id");
  }
  return value;
}

/** Starts the proxy for one tenant and mirrors the child's exit. */
function runTenant(tenantId: string): void {
  if (!existsSync(bootstrapPath)) fail(`bootstrap file not found: ${bootstrapPath}`);

  const command = process.platform === "win32" ? "npx.cmd" : "npx";
  const child = spawn(command, ["tsx", bootstrapPath], {
    cwd: repoRoot,
    env: { ...process.env, TENANT_ID: tenantId },
    stdio: "inherit",
  });

  child.on("error", (error) => fail(`failed to start bootstrap: ${error.message}`));
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

const TOOLS = ["nmap", "nuclei", "trivy", "httpx", "lynis"] as const satisfies readonly EnvironmentTool[];

interface AnalyzeEnvOptions {
  tenant?: string;
  target: string[];
  projectPath?: string;
  nucleiRateLimit?: number;
  output?: string;
  apiUrl?: string;
  projectId?: string;
  send: boolean;
  disableNmap?: boolean;
  disableNuclei?: boolean;
  disableTrivy?: boolean;
  disableHttpx?: boolean;
  disableLynis?: boolean;
}

/**
 * Settings from the process environment and .env files. Highest priority first: process
 * environment, ./.env, <repo>/.env, <repo>/source/.env (where the proxy keeps PORT and TENANT_ID).
 */
function loadEnv(): Record<string, string | undefined> {
  const files = [resolve(repoRoot, "source", ".env"), resolve(repoRoot, ".env"), resolve(process.cwd(), ".env")];
  const merged: Record<string, string | undefined> = {};
  for (const file of files) {
    if (existsSync(file)) Object.assign(merged, parseEnv(readFileSync(file, "utf8")));
  }
  return { ...merged, ...process.env };
}

const env = loadEnv();

/** Defaults from the proxy's own settings; checked only when used because they end up in a URL and in the report. */
const defaultTenant = (): string => checked("TENANT_ID in the environment or .env", parseTenant, env["TENANT_ID"] ?? "default");
const defaultTarget = (): string =>
  `http://localhost:${checked("PORT in the environment or .env", parsePort, env["PORT"] ?? "62197")}`;

interface Inputs {
  tenantId: string;
  targets: string[];
  projectPath: string;
}

/** Asks for whatever was not given by flag, but only in a terminal; pipes and CI keep the defaults. */
async function completeInputs(options: AnalyzeEnvOptions): Promise<Inputs> {
  let tenantId = options.tenant ?? defaultTenant();
  let targets = options.target.length > 0 ? options.target : [defaultTarget()];
  let projectPath = options.projectPath ?? process.cwd();

  const missing = options.tenant === undefined || options.target.length === 0 || options.projectPath === undefined;
  // Prompts go to stderr and are answered on stdin, so both must be a terminal for anyone to see and answer them.
  const interactive = Boolean(process.stdin.isTTY && process.stderr.isTTY);
  if (missing && interactive) {
    const prompter = createPrompter();
    try {
      if (options.tenant === undefined) {
        tenantId = await prompter.ask("Tenant id", { default: tenantId, validate: parseTenant });
      }
      if (options.projectPath === undefined) {
        projectPath = await prompter.ask("Project directory to scan (Trivy)", { default: projectPath, validate: parseDirectory });
      }
      if (options.target.length === 0) {
        const answer = await prompter.ask("Target URL(s) to scan, comma separated", {
          default: defaultTarget(),
          validate: (value) => (parseTargetList(value), value),
        });
        targets = parseTargetList(answer);
      }
    } finally {
      prompter.close();
    }
  }

  return {
    tenantId: checked("--tenant", parseTenant, tenantId),
    targets: checked("--target", parseTargetList, targets.join(",")),
    projectPath: checked("--project-path", parseDirectory, projectPath),
  };
}

interface SendSettings {
  apiUrl: string;
  projectId: string;
  apiKey: string;
}

/** What is missing to upload the report, so the user hears about it before a long analysis, not after. */
function resolveSend(options: AnalyzeEnvOptions): { settings?: SendSettings; missing: string[] } {
  // The key is read only from the environment or .env, never from an argument, so it stays out of shell history and `ps`.
  const apiKey = env["TESSERA_API_KEY"]?.trim();
  const missing: string[] = [];
  if (!options.apiUrl) missing.push("--api-url (TESSERA_API_URL)");
  if (!options.projectId) missing.push("--project-id (TESSERA_PROJECT_ID)");
  if (!apiKey) missing.push("TESSERA_API_KEY in .env");
  if (missing.length > 0 || !options.apiUrl || !options.projectId || !apiKey) return { missing };
  return {
    settings: {
      // Values from the environment skip commander's parsers, so every one is checked here.
      apiUrl: checked("--api-url / TESSERA_API_URL", parseApiUrl, options.apiUrl),
      projectId: checked("--project-id / TESSERA_PROJECT_ID", parseProjectId, options.projectId),
      apiKey,
    },
    missing,
  };
}

async function analyzeEnvironment(options: AnalyzeEnvOptions): Promise<void> {
  // Cheap checks first: a mistake should cost the user seconds, not the length of the scan.
  const outputFile = options.output === undefined ? undefined : checked("--output", parseOutputFile, options.output);
  const disabled = TOOLS.filter((tool) => options[`disable${tool[0]!.toUpperCase()}${tool.slice(1)}` as keyof AnalyzeEnvOptions]);
  const enabled = TOOLS.filter((tool) => !disabled.includes(tool));
  if (enabled.length === 0) fail("every tool is disabled; nothing to run");
  const send = options.send ? resolveSend(options) : undefined;

  const { tenantId, targets, projectPath } = await completeInputs(options);

  if (send && !send.settings) {
    console.error(`Tessera: the report will not be uploaded, missing ${send.missing.join(", ")} (use --no-send to silence this)`);
  }
  console.error(`Tessera: analyzing ${targets.join(", ")} as tenant ${tenantId}`);

  const { expectedMs, learned } = loadExpectedDurations();
  const progress = createProgress(enabled, process.stderr, {
    expectedMs,
    basis: enabled.every((tool) => learned.has(tool)) ? "previous runs" : "typical timings",
  });

  const analyzer = new EnvironmentAnalyzer(new ExecFileRunner());
  try {
    const result = await analyzer.analyze({
      tenantId,
      targets,
      projectPath,
      nucleiRateLimit: options.nucleiRateLimit,
      disabled,
      onProgress: (event) => progress.update(event),
    });
    progress.stop();

    const completed: Partial<Record<EnvironmentTool, number>> = {};
    for (const tool of TOOLS) {
      const run = result[tool];
      if (run.status === "ok") completed[tool] = run.durationMs;
    }
    saveDurations(completed);

    const json = JSON.stringify(result, null, 2);
    // stdout carries only the report so it can be piped; everything else goes to stderr.
    console.log(json);
    if (outputFile) saveReport(outputFile, json);
    if (send?.settings) await sendReport(send.settings, json);
  } catch (error) {
    progress.stop();
    if (error instanceof EnvironmentInputError) fail(error.message);
    throw error;
  }
}

/** A failed save is reported but must not stop the upload: the analysis result is the expensive part. */
function saveReport(file: string, json: string): void {
  try {
    writeFileSync(file, `${json}\n`);
    console.error(`Tessera: report saved to ${file}`);
  } catch (error) {
    console.error(`Tessera: failed to save report to ${file}: ${error instanceof Error ? error.message : error}`);
    process.exitCode = 1;
  }
}

const SEND_TIMEOUT_MS = 30_000;

/** Control plane route that receives `tessera.environment/v1` snapshots (ADR-0016). */
function snapshotsUrl(apiUrl: string, projectId: string): string {
  return `${apiUrl.replace(/\/+$/, "")}/api/v1/tenants/${projectId}/environment-snapshots`;
}

/** Upload failure is reported but never discards the report that was already printed. */
async function sendReport({ apiUrl, projectId, apiKey }: SendSettings, json: string): Promise<void> {
  const url = snapshotsUrl(apiUrl, projectId);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "idempotency-key": randomUUID(),
      },
      body: json,
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`server answered ${response.status}: ${await responseMessage(response)}`);
    }
    const receipt = (await response.json()) as { snapshotId?: string };
    console.error(`Tessera: report sent to ${url} (snapshot ${receipt.snapshotId ?? "unknown"})`);
  } catch (error) {
    console.error(`Tessera: failed to send report to ${url}: ${error instanceof Error ? error.message : error}`);
    process.exitCode = 1;
  }
}

/** The server's `message` field when present, never the request. */
async function responseMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { message?: string | string[] };
    return [body.message ?? response.statusText].flat().join("; ");
  } catch {
    return response.statusText;
  }
}

const REDIS_TIMEOUT_MS = 5_000;

/**
 * `tessera fetch`: pulls the project's active policies from the dashboard, verifies them, builds every tool they name
 * and stores them in Redis, where the proxy reads them at startup and a running proxy picks them up. Nothing is stored
 * unless every check passes; the policies already in Redis stay active.
 */
async function runFetch(options: { force?: boolean }): Promise<void> {
  // The proxy's own configuration (REDIS_URL, TENANT_ID, DASHBOARD_API_URL, DEPLOYMENT_API_KEY, BUNDLE_PUBLIC_KEY), from the same .env files.
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && process.env[key] === undefined) process.env[key] = value;
  }
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(resolve(repoRoot, ".env"));
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
  const verifier = new BundleVerifier(config.dashboard.publicKey, config.tenantId);
  const redis = new RedisStorage({ url: config.redisUrl });
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      redis.connect(),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("timed out")), REDIS_TIMEOUT_MS); }),
    ]);
  } catch (error) {
    fail(`cannot connect to Redis at REDIS_URL (${error instanceof Error ? error.message : error})`);
  } finally { clearTimeout(timer); }

  try {
    const result = await fetchPolicies({
      fetcher: new BundleFetcher({ tenantId: config.tenantId, apiBaseUrl: config.dashboard.url, deploymentKey: config.dashboard.apiKey }, verifier),
      store: new PolicyStore(redis.tenant(config.tenantId).sub("policy")),
      compile: (bundle) => new PolicySnapshot(bundle, (tenantId) => redis.tenant(tenantId)),
      force: options.force,
    });
    const summary = result.summary
      ? ` (${result.summary.global} global, ${result.summary.environment} environment, ${result.summary.endpointSteps} endpoint steps on ${result.summary.endpoints} endpoints)`
      : "";
    if (result.status === "unchanged") {
      console.error(`Tessera: policies are up to date; Redis holds the active version ${result.version}${summary}`);
    } else {
      console.error(`Tessera: stored policy ${result.version}${summary} for project ${config.tenantId}`);
      console.error(result.previousVersion
        ? `Tessera: replaced ${result.previousVersion}; running proxies switch to it within 30 seconds`
        : "Tessera: the proxy can start now");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const hint = error instanceof BundleVerificationError
      ? "; check BUNDLE_PUBLIC_KEY and TENANT_ID"
      : /returned 404/.test(message) ? "; activate a policy for this project in the dashboard first" : "";
    fail(`fetch failed, Redis was not changed: ${message}${hint}`);
  } finally {
    await redis.disconnect();
  }
}

const program = new Command();

program
  .name("tessera")
  .description("Tessera runtime security proxy")
  .option("--install", "install every dependency Tessera needs: npm packages, scanners, Redis, .env")
  .option("--analyze-env", "run the environment analyzer with every tool enabled")
  .option("--tenant <id>", "tenant to analyze (default: TENANT_ID from source/.env)", asArgument(parseTenant))
  .option("--target <target>", "http(s) URL, hostname or IP to scan; repeatable (default: the local proxy)", collectTargets, [] as string[])
  .option("--project-path <path>", "project directory for the Trivy scan (default: current directory)", asArgument(parseDirectory))
  .option("--nuclei-rate-limit <rps>", "nuclei requests per second, 1-1000", asArgument(parseRateLimit))
  .option("--output <file>", "also save the JSON report to this file", asArgument(parseOutputFile))
  .option("--api-url <url>", "control plane base URL, e.g. https://tessera.example.com (env: TESSERA_API_URL)", asArgument(parseApiUrl), env["TESSERA_API_URL"])
  .option("--project-id <id>", "control plane project id the report belongs to (env: TESSERA_PROJECT_ID)", asArgument(parseProjectId), env["TESSERA_PROJECT_ID"])
  .option("--no-send", "do not send the report to the server");

for (const tool of TOOLS) {
  program.option(`--disable-${tool}`, `skip ${tool} during --analyze-env`);
}

program.action(async (options: AnalyzeEnvOptions & { analyzeEnv?: boolean; install?: boolean }) => {
  if (options.install) {
    await runInstall(repoRoot);
    return;
  }
  if (!options.analyzeEnv) {
    program.help({ error: true });
  }
  await analyzeEnvironment(options);
});

program
  .command("project")
  .description("run Tessera for the chosen tenant (run `tessera fetch` first)")
  .argument("<tenant>", "project id (24-character hex)", parseProxyTenant)
  .action((tenant: string) => runTenant(tenant));

program
  .command("fetch")
  .description("fetch the project's active policies from the dashboard into Redis")
  .option("--force", "download and store again even when Redis holds the active version")
  .action((options: { force?: boolean }) => runFetch(options));

program.parseAsync().catch((error: unknown) => {
  console.error("Tessera:", error instanceof Error ? error.message : error);
  process.exit(1);
});
