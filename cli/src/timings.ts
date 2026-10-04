import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { EnvironmentTool } from "../../source/core/environment-analysis";

/** Rough durations on a typical machine, used until a tool has completed once here. */
export const TYPICAL_DURATIONS_MS: Record<EnvironmentTool, number> = {
  nmap: 15_000,
  nuclei: 45_000,
  trivy: 5_000,
  httpx: 5_000,
  lynis: 140_000,
};

// Anything outside this range in the history file is treated as corrupt, not as a measurement.
const MIN_PLAUSIBLE_MS = 100;
const MAX_PLAUSIBLE_MS = 2 * 60 * 60_000;
/** How many past runs are kept per tool. The slowest of them is the estimate, so one lucky run cannot make it optimistic. */
const KEPT_RUNS = 3;

export type DurationBasis = "previous runs" | "typical timings";

export interface ExpectedDurations {
  expectedMs: Record<EnvironmentTool, number>;
  /** Tools whose estimate comes from a past run on this machine. */
  learned: ReadonlySet<EnvironmentTool>;
}

export const defaultTimingsPath = (): string => join(homedir(), ".tessera", "analysis-timings.json");

type History = Partial<Record<EnvironmentTool, number[]>>;

const plausible = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= MIN_PLAUSIBLE_MS && value <= MAX_PLAUSIBLE_MS;

function readHistory(path: string): History {
  try {
    const data: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof data !== "object" || data === null || Array.isArray(data)) return {};
    const history: History = {};
    for (const tool of Object.keys(TYPICAL_DURATIONS_MS) as EnvironmentTool[]) {
      const value = (data as Record<string, unknown>)[tool];
      const runs = Array.isArray(value) ? value.filter(plausible).slice(-KEPT_RUNS) : [];
      if (runs.length > 0) history[tool] = runs;
    }
    return history;
  } catch {
    return {};
  }
}

/** Expected duration per tool: the slowest of its last few successful runs here, otherwise the typical value. Never throws. */
export function loadExpectedDurations(path: string = defaultTimingsPath()): ExpectedDurations {
  const history = readHistory(path);
  const expectedMs = { ...TYPICAL_DURATIONS_MS };
  const learned = new Set<EnvironmentTool>();
  for (const [tool, runs] of Object.entries(history) as Array<[EnvironmentTool, number[]]>) {
    expectedMs[tool] = Math.max(...runs);
    learned.add(tool);
  }
  return { expectedMs, learned };
}

/** Remembers how long the tools that completed took. Best effort: a read-only home must not break the run. */
export function saveDurations(durationsMs: Partial<Record<EnvironmentTool, number>>, path: string = defaultTimingsPath()): void {
  const merged = { ...readHistory(path) };
  for (const [tool, ms] of Object.entries(durationsMs) as Array<[EnvironmentTool, number]>) {
    if (plausible(ms)) merged[tool] = [...(merged[tool] ?? []), Math.round(ms)].slice(-KEPT_RUNS);
  }
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, `${JSON.stringify(merged, null, 2)}\n`, { mode: 0o600 });
  } catch {
    /* ignored */
  }
}
