#!/usr/bin/env node

/**
 * Cross-platform runner for AheadGuard smoke tests.
 *
 * Usage:
 *   node scripts/run-smoke.mjs          # Default: runs smoke suite with opt-in tests skipped
 *   node scripts/run-smoke.mjs --live   # Sets RUN_LIVE_SMOKE_TEST=true (TinyFish live probe)
 *   node scripts/run-smoke.mjs --prod   # Sets RUN_PROD_SMOKE_TEST=true (Vercel deployment contract check)
 *   node scripts/run-smoke.mjs --db     # Sets RUN_DB_SMOKE_TEST=true (Strict production DB persistence check)
 *   node scripts/run-smoke.mjs --post   # Sets RUN_LIVE_PROD_INVESTIGATION=true (Live billable investigation probe)
 *   node scripts/run-smoke.mjs --persistence # Delegates to scripts/verify-persistence.mjs
 */

import { spawn } from "node:child_process";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const isPersistence = args.includes("--persistence");

if (isPersistence) {
  const runner = resolve(process.cwd(), "scripts", "verify-persistence.mjs");
  const forwardArgs = args.filter((a) => a !== "--persistence");
  const child = spawn(process.execPath, [runner, ...forwardArgs], {
    stdio: "inherit",
    env: process.env,
  });
  child.on("close", (code) => {
    process.exit(code ?? 0);
  });
} else {
  const isLive = args.includes("--live");
  const isProd = args.includes("--prod");
  const isDb = args.includes("--db");
  const isPost = args.includes("--post");

  const env = {
    ...process.env,
  };

  if (isLive) {
    env.RUN_LIVE_SMOKE_TEST = "true";
  }

  if (isProd) {
    env.RUN_PROD_SMOKE_TEST = "true";
  }

  if (isDb) {
    env.RUN_DB_SMOKE_TEST = "true";
  }

  if (isPost) {
    env.RUN_LIVE_PROD_INVESTIGATION = "true";
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
}
