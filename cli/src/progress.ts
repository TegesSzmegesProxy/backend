import type { Writable } from "node:stream";
import type { EnvironmentTool, ToolProgress } from "../../source/core/environment-analysis";
import type { DurationBasis } from "./timings";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BAR_WIDTH = 20;
/** The bar never claims completion before every tool has actually finished. */
const MAX_UNFINISHED_FRACTION = 0.99;
/** Remaining time is shown in steps this big so the number does not jitter. */
const ETA_STEP_MS = 5_000;

export interface Progress {
  /** Feed analyzer events here. */
  update(event: ToolProgress): void;
  /** Stops the animation and leaves the final state on screen. */
  stop(): void;
}

export interface ProgressOptions {
  /** Expected duration per tool; the run takes about as long as the slowest tool because they run in parallel. */
  expectedMs: Record<EnvironmentTool, number>;
  basis: DurationBasis;
  interactive?: boolean;
  now?: () => number;
  intervalMs?: number;
}

/** "1m05s" / "42s". */
export function formatElapsed(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m${String(seconds % 60).padStart(2, "0")}s`;
}

const STATUS_MARK = { ok: "✓", failed: "✗" } as const;

/**
 * Shows which tools are running and which have finished, with an estimate of the time left. On a terminal it
 * redraws one status line; otherwise it prints one plain line per event so logs stay readable.
 */
export function createProgress(
  tools: readonly EnvironmentTool[],
  output: Writable = process.stderr,
  options: ProgressOptions,
): Progress {
  const interactive = options.interactive ?? Boolean((output as { isTTY?: boolean }).isTTY);
  const now = options.now ?? Date.now;
  const started = now();
  const toolStart = new Map<EnvironmentTool, number>();
  const running = new Set<EnvironmentTool>();
  const finishedTools = new Set<EnvironmentTool>();
  const done: string[] = [];
  let frame = 0;
  let timer: NodeJS.Timeout | undefined;

  const unfinished = () => tools.filter((tool) => !finishedTools.has(tool));
  const expectedTotal = Math.max(0, ...tools.map((tool) => options.expectedMs[tool]));

  /** Time left until the slowest unfinished tool reaches its estimate; undefined once all of them are overdue. */
  const remainingMs = (): number | undefined => {
    const left = unfinished().map((tool) => options.expectedMs[tool] - (now() - (toolStart.get(tool) ?? started)));
    const positive = left.filter((ms) => ms > 0);
    return positive.length > 0 ? Math.max(...positive) : undefined;
  };

  const etaText = (): string => {
    if (unfinished().length === 0) return "";
    const remaining = remainingMs();
    if (remaining === undefined) return ", taking longer than expected";
    return `, about ${formatElapsed(Math.ceil(remaining / ETA_STEP_MS) * ETA_STEP_MS)} left`;
  };

  const fraction = (): number => {
    if (unfinished().length === 0) return 1;
    const byTime = expectedTotal > 0 ? (now() - started) / expectedTotal : 0;
    const byCount = finishedTools.size / tools.length;
    return Math.min(MAX_UNFINISHED_FRACTION, Math.max(byTime, byCount));
  };

  const render = () => {
    const filled = Math.floor(fraction() * BAR_WIDTH);
    const bar = "█".repeat(filled) + "░".repeat(BAR_WIDTH - filled);
    const doneText = done.length > 0 ? `  done: ${done.join(" ")}` : "";
    const runningText = running.size > 0 ? `  running: ${[...running].join(", ")}` : "";
    output.write(
      `\r\x1b[2K${FRAMES[frame++ % FRAMES.length]} ${bar} ${finishedTools.size}/${tools.length}${doneText}${runningText}  ${formatElapsed(now() - started)} elapsed${etaText()}`,
    );
  };

  if (tools.length > 0) {
    const slowest = tools.reduce((a, b) => (options.expectedMs[b] > options.expectedMs[a] ? b : a));
    output.write(
      `Tessera: expected time about ${formatElapsed(expectedTotal)} (based on ${options.basis}; tools run in parallel, ${slowest} is the slowest)\n`,
    );
  }

  if (interactive && tools.length > 0) {
    render();
    timer = setInterval(render, options.intervalMs ?? 200);
    timer.unref();
  }

  return {
    update(event) {
      // Tools the user disabled are not part of the run, so they are not shown.
      if (!tools.includes(event.tool)) return;
      if (event.phase === "started") {
        running.add(event.tool);
        toolStart.set(event.tool, now());
        if (!interactive) output.write(`Tessera: ${event.tool} started\n`);
        return;
      }
      running.delete(event.tool);
      finishedTools.add(event.tool);
      if (event.status === "skipped") return;
      done.push(`${event.tool}${STATUS_MARK[event.status]}`);
      if (interactive) render();
      else {
        output.write(
          `Tessera: ${event.tool} ${event.status} after ${formatElapsed(event.durationMs)} (${finishedTools.size}/${tools.length}${etaText()})\n`,
        );
      }
    },
    stop() {
      if (timer) clearInterval(timer);
      if (interactive && tools.length > 0) {
        render();
        output.write("\n");
      }
    },
  };
}
