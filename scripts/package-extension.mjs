#!/usr/bin/env node

/**
 * AheadGuard AI — Chrome Extension Packaging Script
 *
 * Builds, validates, and packages the Manifest V3 Chrome Extension
 * into public and root ZIP archives for direct website download and installation.
 */

import { execSync } from "node:child_process";
import { existsSync, rmSync, readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, "..");
const extensionDir = resolve(rootDir, "extension");
const publicDir = resolve(rootDir, "public");

console.log("============================================================");
console.log(" AheadGuard AI — Packaging Chrome Extension (Manifest V3)");
console.log("============================================================");

// Step 1: Compile extension bundles with esbuild
console.log("\n[1/5] Compiling extension bundles with esbuild...");
execSync("node build-extension.mjs", { cwd: rootDir, stdio: "inherit" });

// Step 2: Validate manifest.json
console.log("\n[2/5] Validating extension manifest...");
const manifestPath = resolve(extensionDir, "manifest.json");
if (!existsSync(manifestPath)) {
  console.error("❌ Fatal: extension/manifest.json not found!");
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
if (manifest.manifest_version !== 3) {
  console.error(`❌ Fatal: Expected manifest_version 3, got ${manifest.manifest_version}`);
  process.exit(1);
}

const version = manifest.version || "3.0.0";
console.log(`  ✓ Manifest valid: "${manifest.name}" v${version} (MV3)`);

// Step 3: Verify all required runtime files
console.log("\n[3/5] Verifying required runtime distribution files...");
const filesToZip = [
  "manifest.json",
  "popup.html",
  "popup.css", // Essential stylesheet
  "background.js", // Background service worker
  "popup.js", // Main popup logic
  "content.js", // Isolated content script
  "icons/icon16.png",
  "icons/icon48.png",
  "icons/icon128.png",
];

for (const relFile of filesToZip) {
  const absFile = resolve(extensionDir, relFile);
  if (!existsSync(absFile)) {
    console.error(`❌ Fatal: Missing required extension file: ${relFile}`);
    process.exit(1);
  }
  const stat = statSync(absFile);
  console.log(`  ✓ ${relFile.padEnd(20)} (${(stat.size / 1024).toFixed(1)} KB)`);
}

// Ensure public directory exists
mkdirSync(publicDir, { recursive: true });

// Step 4: Package ZIP distributions
console.log("\n[4/5] Creating clean distribution ZIP packages...");

const canonicalZipName = "aheadguard-ai-chrome-extension.zip";
const versionedZipName = `aheadguard-extension-v${version}.zip`;

const targetPaths = [
  resolve(publicDir, canonicalZipName),
  resolve(publicDir, versionedZipName),
  resolve(rootDir, canonicalZipName),
  resolve(rootDir, versionedZipName),
];

function createZipArchive(targetPath, fileList, cwd) {
  let created = false;
  let lastErr = null;

  // Attempt 1: Standard zip command (Linux / macOS / environments with zip installed)
  try {
    execSync(`zip -r "${targetPath}" ${fileList.join(" ")}`, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    created = existsSync(targetPath) && statSync(targetPath).size > 0;
  } catch (err) {
    lastErr = err;
  }

  // Attempt 2: tar -a -cf (Native on Windows 10/11, macOS, and Linux bsdtar)
  if (!created) {
    try {
      execSync(`tar -a -cf "${targetPath}" ${fileList.join(" ")}`, {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
      });
      created = existsSync(targetPath) && statSync(targetPath).size > 0;
    } catch (err) {
      lastErr = err;
    }
  }

  // Attempt 3: PowerShell Compress-Archive (Windows fallback)
  if (!created && process.platform === "win32") {
    try {
      const psItems = fileList.map((f) => `'${f}'`).join(",");
      const psCmd = `powershell -NoProfile -Command "Compress-Archive -Path ${psItems} -DestinationPath '${targetPath}' -Force"`;
      execSync(psCmd, { cwd, stdio: ["ignore", "pipe", "pipe"] });
      created = existsSync(targetPath) && statSync(targetPath).size > 0;
    } catch (err) {
      lastErr = err;
    }
  }

  if (!created) {
    throw new Error(`Failed to create ZIP package ${targetPath}: ${lastErr?.message || "No zip utility available"}`);
  }
}

for (const targetPath of targetPaths) {
  if (existsSync(targetPath)) {
    rmSync(targetPath);
  }
  createZipArchive(targetPath, filesToZip, extensionDir);
  console.log(`  ✓ Built package: ${targetPath}`);
}

// Step 5: Compute checksums and write release metadata
console.log("\n[5/5] Generating release metadata & checksums...");
const canonicalZipPath = resolve(publicDir, canonicalZipName);
const zipBuffer = readFileSync(canonicalZipPath);
const sha256 = createHash("sha256").update(zipBuffer).digest("hex");
const sizeBytes = zipBuffer.length;
const sizeKb = (sizeBytes / 1024).toFixed(1);

const releaseMetadata = {
  name: manifest.name,
  version: version,
  manifestVersion: manifest.manifest_version,
  releaseDate: new Date().toISOString().split("T")[0],
  fileName: canonicalZipName,
  downloadUrl: `/${canonicalZipName}`,
  versionedDownloadUrl: `/${versionedZipName}`,
  sha256: sha256,
  sizeBytes: sizeBytes,
  sizeFormatted: `${sizeKb} KB`,
  files: filesToZip,
  compatibility: {
    target: "Chromium (Manifest V3)",
    supportedBrowsers: ["Google Chrome", "Microsoft Edge", "Brave", "Opera", "Arc"],
    developerModeRequired: true,
    backendUrl: "https://aheadguard-ai.vercel.app",
    permissions: manifest.permissions || [],
    hostPermissions: manifest.host_permissions || [],
  },
};

const releaseJsonPath = resolve(publicDir, "extension-release.json");
writeFileSync(releaseJsonPath, JSON.stringify(releaseMetadata, null, 2), "utf8");
console.log(`  ✓ Release metadata saved: ${releaseJsonPath}`);
console.log(`  ✓ Package SHA-256: ${sha256}`);
console.log(`  ✓ Package Size: ${sizeKb} KB (${sizeBytes} bytes)`);

console.log("\n============================================================");
console.log(`✅ AheadGuard Extension v${version} packaged and ready for deployment!`);
console.log(`   Canonical URL: /${canonicalZipName}`);
console.log("============================================================\n");
