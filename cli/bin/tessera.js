#!/usr/bin/env node
// Launcher: runs the TypeScript CLI with the tsx installed next to it, so it works from any directory.
const { spawnSync } = require("node:child_process");
const { resolve } = require("node:path");

const cliRoot = resolve(__dirname, "..");
const repoRoot = resolve(cliRoot, "..");

// `--install` starts here: the TypeScript CLI cannot load before its npm packages and the proxy's (zod) exist.
if (process.argv.includes("--install")) {
  const [major, minor] = process.versions.node.split(".").map(Number);
  // util.parseEnv, used by the CLI, arrived in Node 20.12.
  if (major < 20 || (major === 20 && minor < 12)) {
    console.error(`Tessera: Node.js 20.12 or newer is required, found ${process.versions.node}`);
    process.exit(1);
  }
  console.error("Tessera: step 1 of 2, npm packages (proxy and CLI)");
  for (const dir of [repoRoot, cliRoot]) {
    console.error(`\n  npm install in ${dir}`);
    // `npm install`, not `npm ci`: ci deletes node_modules, including the tsx this launcher is about to run.
    const result = spawnSync("npm", ["install", "--no-audit", "--no-fund"], { cwd: dir, stdio: "inherit", shell: process.platform === "win32" });
    if (result.status !== 0) {
      console.error(`Tessera: npm install failed in ${dir}`);
      process.exit(result.status ?? 1);
    }
  }
  console.error("\nTessera: step 2 of 2, system tools\n");
}

let tsxCli;
try {
  tsxCli = require.resolve("tsx/cli");
} catch {
  console.error("Tessera: npm packages are not installed yet; run `tessera --install` first");
  process.exit(1);
}
const entry = resolve(cliRoot, "src", "cli.ts");

const result = spawnSync(process.execPath, [tsxCli, entry, ...process.argv.slice(2)], { stdio: "inherit" });
if (result.signal) process.kill(process.pid, result.signal);
process.exit(result.status ?? 1);
