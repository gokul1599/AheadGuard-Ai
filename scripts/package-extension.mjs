#!/usr/bin/env node

/**
 * AheadGuard AI — Chrome Extension Packaging Script
 * Generates aheadguard-extension-v2.1.0.zip for Chrome Web Store distribution.
 */

import { execSync } from "node:child_process";
import { existsSync, rmSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, "..");
const extensionDir = resolve(rootDir, "extension");

const manifest = JSON.parse(readFileSync(resolve(extensionDir, "manifest.json"), "utf8"));
const version = manifest.version || "3.0.0";
const zipName = `aheadguard-extension-v${version}.zip`;
const zipPath = resolve(rootDir, zipName);

console.log("==> Step 1: Compiling extension bundles with esbuild...");
execSync("node build-extension.mjs", { cwd: rootDir, stdio: "inherit" });

console.log("==> Step 2: Preparing clean distribution package...");
if (existsSync(zipPath)) {
  rmSync(zipPath);
}

// Files to bundle in extension zip:
// manifest.json, popup.html, background.js, popup.js, content.js, icons/
const filesToZip = [
  "manifest.json",
  "popup.html",
  "background.js",
  "popup.js",
  "content.js",
  "icons/icon16.png",
  "icons/icon48.png",
  "icons/icon128.png",
];

// Verify all files exist
for (const file of filesToZip) {
  const filePath = resolve(extensionDir, file);
  if (!existsSync(filePath)) {
    console.error(`Missing required extension file: ${file}`);
    process.exit(1);
  }
}

console.log(`==> Step 3: Zipping extension files into ${zipName}...`);
const zipCommand = `zip -r "${zipPath}" ${filesToZip.join(" ")}`;
execSync(zipCommand, { cwd: extensionDir, stdio: "inherit" });

console.log(`✅ AheadGuard Chrome Extension packaged successfully: ${zipPath}`);
