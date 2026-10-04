import { execFile } from 'node:child_process';
import type { ToolFailureKind } from './types';

export interface CommandResult {
    stdout: string;
    stderr: string;
    exitCode: number;
}

export interface RunOptions {
    timeoutMs: number;
}

/** Port for running an external binary. Implementations must not use a shell. */
export interface CommandRunner {
    run(binary: string, args: string[], options: RunOptions): Promise<CommandResult>;
}

/** A tool run that failed in a way the analyzer records instead of propagating. */
export class CommandError extends Error {
    constructor(
        public readonly kind: ToolFailureKind,
        message: string
    ) {
        super(message);
        this.name = 'CommandError';
    }
}

const MAX_BUFFER_BYTES = 64 * 1024 * 1024;

export class ExecFileRunner implements CommandRunner {
    run(binary: string, args: string[], { timeoutMs }: RunOptions): Promise<CommandResult> {
        return new Promise((resolve, reject) => {
            const child = execFile(
                binary,
                args,
                { timeout: timeoutMs, maxBuffer: MAX_BUFFER_BYTES, encoding: 'utf8' },
                (error, stdout, stderr) => {
                    if (!error) {
                        resolve({ stdout, stderr, exitCode: 0 });
                        return;
                    }
                    if ('code' in error && error.code === 'ENOENT') {
                        reject(new CommandError('missing', `${binary} is not installed`));
                    } else if (error.killed) {
                        reject(new CommandError('timeout', `${binary} timed out after ${timeoutMs}ms`));
                    } else if (typeof error.code === 'number') {
                        // A non-zero exit still carries output; callers decide whether it is usable.
                        resolve({ stdout, stderr, exitCode: error.code });
                    } else {
                        reject(error);
                    }
                }
            );
            // httpx and nuclei read targets from stdin while it is a pipe; close it so they never wait.
            child.stdin?.end();
        });
    }
}
