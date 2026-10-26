import * as esbuild from "esbuild";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function build() {
  console.log("Building AheadGuard Chrome Extension...");

  const baseConfig = {
    bundle: true,
    sourcemap: false,
    minify: false,
    target: ["chrome110"],
    logLevel: "info",
  };

  // 1. Build Background Service Worker (ES Module for MV3)
  await esbuild.build({
    ...baseConfig,
    entryPoints: [path.join(__dirname, "extension/src/background.ts")],
    outfile: path.join(__dirname, "extension/background.js"),
    format: "esm",
  });

  // 2. Build Popup script
  await esbuild.build({
    ...baseConfig,
    entryPoints: [path.join(__dirname, "extension/src/popup.ts")],
    outfile: path.join(__dirname, "extension/popup.js"),
    format: "esm",
  });

  // 3. Build Content script (IIFE for isolated page execution)
  await esbuild.build({
    ...baseConfig,
    entryPoints: [path.join(__dirname, "extension/src/content.ts")],
    outfile: path.join(__dirname, "extension/content.js"),
    format: "iife",
  });

  console.log("AheadGuard Chrome Extension build complete! Artifacts located in /extension");
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
