import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";

export interface AskOptions {
  /** Used when the answer is empty. */
  default?: string;
  /** Returns the cleaned value, or throws with a message to show before asking again. */
  validate?: (value: string) => string;
}

export interface Prompter {
  ask(question: string, options?: AskOptions): Promise<string>;
  close(): void;
}

const MAX_ATTEMPTS = 5;

/** Line-based prompts on the given streams (stdin/stderr by default, so stdout stays pipeable). */
export function createPrompter(input: Readable = process.stdin, output: Writable = process.stderr): Prompter {
  const rl = createInterface({ input });
  // The line iterator buffers, so answers that arrive before the question is asked are not lost.
  const lines = rl[Symbol.asyncIterator]();
  return {
    async ask(question, { default: fallback, validate } = {}) {
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        const suffix = fallback ? ` [${fallback}]` : "";
        output.write(`${question}${suffix}: `);
        const line = await lines.next();
        if (line.done) throw new Error("input closed before an answer was given");
        const answer = line.value.trim() || fallback || "";
        try {
          return validate ? validate(answer) : answer;
        } catch (error) {
          output.write(`  ${error instanceof Error ? error.message : error}\n`);
        }
      }
      throw new Error(`no valid answer to "${question}"`);
    },
    close: () => rl.close(),
  };
}
