#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseEnv } from "node:util";
import { Command, InvalidArgumentError } from "commander";
import {
  EnvironmentAnalyzer,
  EnvironmentInputError,
  ExecFileRunner,
} from "../../source/core/environment-analysis";

const repoRoot = resolve(__dirname, "..", "..");
const bootstrapPath = resolve(repoRoot, "source", "bootstrap.ts");

// Same format the environment analyzer accepts.
const TENANT_ID = /^[A-Za-z0-9_-]{1,40}$/;

function parseTenant(value: string): string {
  if (!TENANT_ID.test(value)) {
    throw new InvalidArgumentError("must be 1-40 characters of letters, digits, '_' or '-'");
  }
  return value;
}

// Mongo ObjectId of the project (tenant) in the control plane; it is the route tenant, unlike the proxy's TENANT_ID slug.
const PROJECT_ID = /^[a-f0-9]{24}$/i;

function parseProjectId(value: string): string {
  if (!PROJECT_ID.test(value)) {
    throw new InvalidArgumentError("must be the project's 24-character hex id");
  }
  return value;
}

function parseRateLimit(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new InvalidArgumentError("must be a positive integer");
  }
  return parsed;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function fail(message: string): never {
  console.error(`Tessera: ${message}`);
  process.exit(1);
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

const TOOLS = ["nmap", "nuclei", "trivy", "httpx", "lynis"] as const;
type Tool = (typeof TOOLS)[number];

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

/** PORT and TENANT_ID as the proxy itself will see them. */
function proxyEnv(): { port: string; tenant: string } {
  return { port: env["PORT"] ?? "62197", tenant: env["TENANT_ID"] ?? "default" };
}

async function analyzeEnvironment(options: AnalyzeEnvOptions): Promise<void> {
  const defaults = proxyEnv();
  const tenantId = options.tenant ?? defaults.tenant;
  const targets = options.target.length > 0 ? options.target : [`http://localhost:${defaults.port}`];
  const disabled = TOOLS.filter((tool) => options[`disable${tool[0]!.toUpperCase()}${tool.slice(1)}` as keyof AnalyzeEnvOptions]);

  const analyzer = new EnvironmentAnalyzer(new ExecFileRunner());
  try {
    const result = await analyzer.analyze({
      tenantId,
      targets,
      projectPath: resolve(options.projectPath ?? process.cwd()),
      nucleiRateLimit: options.nucleiRateLimit,
      disabled,
    });
    const json = JSON.stringify(result, null, 2);
    // stdout carries only the report so it can be piped; everything else goes to stderr.
    console.log(json);
    if (options.output) {
      writeFileSync(resolve(options.output), `${json}\n`);
      console.error(`Tessera: report saved to ${resolve(options.output)}`);
    }
    if (options.send) await sendReport(options, json);
  } catch (error) {
    if (error instanceof EnvironmentInputError) fail(error.message);
    throw error;
  }
}

const SEND_TIMEOUT_MS = 30_000;

/** Control plane route that receives `tessera.environment/v1` snapshots (ADR-0016). */
function snapshotsUrl(apiUrl: string, projectId: string): string {
  return `${apiUrl.replace(/\/+$/, "")}/api/v1/tenants/${projectId}/environment-snapshots`;
}

/** Upload failure is reported but never discards the report that was already printed. */
async function sendReport(options: AnalyzeEnvOptions, json: string): Promise<void> {
  const { apiUrl, projectId } = options;
  // The key is read only from the environment or .env, never from an argument, so it stays out of shell history and `ps`.
  const apiKey = env["TESSERA_API_KEY"];
  if (!apiUrl || !apiKey || !projectId) {
    console.error(
      "Tessera: report not sent; set TESSERA_API_KEY in .env and --api-url (TESSERA_API_URL) and --project-id (TESSERA_PROJECT_ID), or pass --no-send",
    );
    return;
  }
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

const program = new Command();

program
  .name("tessera")
  .description("Tessera runtime security proxy")
  .option("--analyze-env", "run the environment analyzer with every tool enabled")
  .option("--tenant <id>", "tenant to analyze (default: TENANT_ID from source/.env)", parseTenant)
  .option("--target <target>", "http(s) URL, hostname or IP to scan; repeatable (default: the local proxy)", collect, [] as string[])
  .option("--project-path <path>", "project directory for the Trivy scan (default: current directory)")
  .option("--nuclei-rate-limit <rps>", "nuclei requests per second", parseRateLimit)
  .option("--output <file>", "also save the JSON report to this file")
  .option("--api-url <url>", "control plane base URL, e.g. https://tessera.example.com (env: TESSERA_API_URL)", env["TESSERA_API_URL"])
  .option("--project-id <id>", "control plane project id the report belongs to (env: TESSERA_PROJECT_ID)", parseProjectId, env["TESSERA_PROJECT_ID"])
  .option("--no-send", "do not send the report to the server");

for (const tool of TOOLS) {
  program.option(`--disable-${tool}`, `skip ${tool} during --analyze-env`);
}

program.action(async (options: AnalyzeEnvOptions & { analyzeEnv?: boolean }) => {
  if (!options.analyzeEnv) {
    program.help({ error: true });
  }
  await analyzeEnvironment(options);
});

program
  .command("project")
  .description("run Tessera for the chosen tenant")
  .argument("<tenant>", "tenant id", parseTenant)
  .action((tenant: string) => runTenant(tenant));

program.parseAsync().catch((error) => {
  console.error("Tessera:", error instanceof Error ? error.message : error);
  process.exit(1);
});
