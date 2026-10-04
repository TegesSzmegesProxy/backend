#!/usr/bin/env node
// Launcher: runs the TypeScript CLI with the tsx installed next to it, so it works from any directory.
const { spawnSync } = require("node:child_process");
const { resolve } = require("node:path");

const tsxCli = require.resolve("tsx/cli");
const entry = resolve(__dirname, "..", "src", "cli.ts");

const result = spawnSync(process.execPath, [tsxCli, entry, ...process.argv.slice(2)], { stdio: "inherit" });
if (result.signal) process.kill(process.pid, result.signal);
process.exit(result.status ?? 1);
