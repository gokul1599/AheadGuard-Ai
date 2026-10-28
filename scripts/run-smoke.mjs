#!/usr/bin/env node

/**
 * Cross-platform runner for AheadGuard smoke tests.
 *
 * Usage:
 *   node scripts/run-smoke.mjs          # Default: runs smoke suite with opt-in tests skipped
 *   node scripts/run-smoke.mjs --live   # Sets RUN_LIVE_SMOKE_TEST=true (TinyFish live probe)
 *   node scripts/run-smoke.mjs --prod   # Sets RUN_PROD_SMOKE_TEST=true (Vercel live deployment check)
 */

import { spawn } from "node:child_process";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const isLive = args.includes("--live");
const isProd = args.includes("--prod");

const env = {
  ...process.env,
};

if (isLive) {
  env.RUN_LIVE_SMOKE_TEST = "true";
}

if (isProd) {
  env.RUN_PROD_SMOKE_TEST = "true";
}

// Directly invoke the project's installed vitest entrypoint via Node.js
// avoiding shell: true and cross-platform binary differences.
const vitestEntry = resolve(process.cwd(), "node_modules", "vitest", "vitest.mjs");

const child = spawn(process.execPath, [vitestEntry, "run", "tests/smoke.test.ts"], {
  stdio: "inherit",
  env,
});

child.on("close", (code) => {
  process.exit(code ?? 0);
});
