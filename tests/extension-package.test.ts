import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

describe("AheadGuard AI Chrome Extension Distribution Package", () => {
  const rootDir = path.resolve(__dirname, "..");
  const publicDir = path.join(rootDir, "public");
  const zipPath = path.join(publicDir, "aheadguard-ai-chrome-extension.zip");
  const releaseJsonPath = path.join(publicDir, "extension-release.json");
  const extensionDir = path.join(rootDir, "extension");

  beforeAll(() => {
    // Ensure extension is built and packaged
    execSync("node scripts/package-extension.mjs", { cwd: rootDir, stdio: "pipe" });
  });

  it("produces aheadguard-ai-chrome-extension.zip in public directory", () => {
    expect(fs.existsSync(zipPath)).toBe(true);
    const stats = fs.statSync(zipPath);
    expect(stats.size).toBeGreaterThan(15_000); // Should be ~25-30 KB
  });

  it("contains all 9 required runtime distribution files in the ZIP", () => {
    const listOutput = execSync(`unzip -l "${zipPath}"`, { encoding: "utf8" });

    const requiredFiles = [
      "manifest.json",
      "popup.html",
      "popup.css",
      "background.js",
      "popup.js",
      "content.js",
      "icons/icon16.png",
      "icons/icon48.png",
      "icons/icon128.png",
    ];

    for (const file of requiredFiles) {
      expect(listOutput).toContain(file);
    }
  });

  it("does not include development artifacts, TypeScript files, or node_modules in the ZIP", () => {
    const listOutput = execSync(`unzip -l "${zipPath}"`, { encoding: "utf8" });

    expect(listOutput).not.toContain("node_modules");
    expect(listOutput).not.toContain(".ts");
    expect(listOutput).not.toContain(".git");
    expect(listOutput).not.toContain(".env");
  });

  it("ensures manifest.json specifies Manifest V3 with production host permissions", () => {
    const manifestPath = path.join(extensionDir, "manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

    expect(manifest.manifest_version).toBe(3);
    expect(manifest.version).toBe("3.0.0");
    expect(manifest.name).toContain("AheadGuard");
    expect(manifest.background?.service_worker).toBe("background.js");
    expect(manifest.action?.default_popup).toBe("popup.html");
    expect(manifest.host_permissions).toContain("https://aheadguard-ai.vercel.app/*");
    expect(manifest.permissions).toContain("activeTab");
    expect(manifest.permissions).toContain("storage");
  });

  it("generates valid public/extension-release.json metadata matching ZIP", () => {
    expect(fs.existsSync(releaseJsonPath)).toBe(true);
    const releaseData = JSON.parse(fs.readFileSync(releaseJsonPath, "utf8"));

    expect(releaseData.name).toContain("AheadGuard");
    expect(releaseData.version).toBe("3.0.0");
    expect(releaseData.manifestVersion).toBe(3);
    expect(releaseData.downloadUrl).toBe("/aheadguard-ai-chrome-extension.zip");
    expect(releaseData.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(releaseData.sizeBytes).toBeGreaterThan(15_000);
    expect(releaseData.compatibility.supportedBrowsers).toContain("Google Chrome");
    expect(releaseData.compatibility.supportedBrowsers).toContain("Microsoft Edge");
    expect(releaseData.compatibility.developerModeRequired).toBe(true);
  });
});
