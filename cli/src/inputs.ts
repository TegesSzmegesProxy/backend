import { accessSync, constants, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { EnvironmentInputError, MAX_RATE_LIMIT, parseTargets } from "../../source/core/environment-analysis";

/** A user-supplied value (flag, prompt answer or environment setting) that cannot be used. */
export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

const TENANT_ID = /^[A-Za-z0-9_-]{1,40}$/;
// Mongo ObjectId of the project (tenant) in the control plane; it is the route tenant, unlike the proxy's TENANT_ID slug.
const PROJECT_ID = /^[a-f0-9]{24}$/i;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function parseTenant(value: string): string {
  const tenant = value.trim();
  if (!TENANT_ID.test(tenant)) throw new InputError("must be 1-40 characters of letters, digits, '_' or '-'");
  return tenant;
}

export function parseProjectId(value: string): string {
  const id = value.trim();
  if (!PROJECT_ID.test(id)) throw new InputError("must be the project's 24-character hex id");
  return id;
}

export function parseRateLimit(value: string): number {
  const text = value.trim();
  const parsed = Number(text);
  if (!/^\d+$/.test(text) || parsed < 1 || parsed > MAX_RATE_LIMIT) {
    throw new InputError(`must be a whole number from 1 to ${MAX_RATE_LIMIT}`);
  }
  return parsed;
}

export function parsePort(value: string): string {
  const text = value.trim();
  if (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65_535) {
    throw new InputError("must be a port number from 1 to 65535");
  }
  return String(Number(text));
}

/** One or more targets separated by commas or whitespace, validated by the analyzer's own rules. */
export function parseTargetList(value: string): string[] {
  const targets = value.split(/[,\s]+/).filter(Boolean);
  if (targets.length === 0) throw new InputError("give at least one target (URL, hostname or IP)");
  try {
    parseTargets(targets);
  } catch (error) {
    if (error instanceof EnvironmentInputError) throw new InputError(error.message);
    throw error;
  }
  return targets;
}

/** What a user types or pastes for a path: optional quotes and a leading ~ that no shell expanded. */
function cleanPath(value: string, home: string): string {
  let text = value.trim();
  if (text.length >= 2 && /^(["']).*\1$/.test(text)) text = text.slice(1, -1);
  if (text === "~" || text.startsWith("~/")) text = home + text.slice(1);
  if (text === "" || text.includes("\0")) throw new InputError("must be a path");
  return resolve(text);
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function can(path: string, mode: number): boolean {
  try {
    accessSync(path, mode);
    return true;
  } catch {
    return false;
  }
}

/** An existing, readable directory, as an absolute path. */
export function parseDirectory(value: string, home: string = homedir()): string {
  const path = cleanPath(value, home);
  if (!isDirectory(path)) throw new InputError(`not a directory: ${path}`);
  if (!can(path, constants.R_OK | constants.X_OK)) throw new InputError(`directory is not readable: ${path}`);
  return path;
}

/** A file the report can be written to. Checked before the analysis so a long run is not lost to a typo. */
export function parseOutputFile(value: string, home: string = homedir()): string {
  const path = cleanPath(value, home);
  if (isDirectory(path)) throw new InputError(`is a directory, not a file: ${path}`);
  let exists = true;
  try {
    statSync(path);
  } catch {
    exists = false;
  }
  if (exists) {
    if (!can(path, constants.W_OK)) throw new InputError(`file is not writable: ${path}`);
    return path;
  }
  const parent = dirname(path);
  if (!isDirectory(parent)) throw new InputError(`directory does not exist: ${parent}`);
  if (!can(parent, constants.W_OK)) throw new InputError(`directory is not writable: ${parent}`);
  return path;
}

/** Base URL of the control plane. The API key is sent to it, so plain http is only allowed for loopback. */
export function parseApiUrl(value: string): string {
  const text = value.trim();
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new InputError("must be a URL such as https://tessera.example.com");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new InputError("must start with https://");
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
    throw new InputError("plain http would send the API key unencrypted; use https:// (http is allowed only for localhost)");
  }
  if (url.username || url.password) throw new InputError("must not contain a username or password");
  if (url.search || url.hash) throw new InputError("must not contain a query string or fragment");
  return text;
}
