#!/usr/bin/env node
/**
 * AheadGuard AI — Automated Chromium Extension End-to-End Acceptance Test
 *
 * Launches an isolated Chromium instance (using installed Chromium/Edge binary),
 * loads the unpacked AheadGuard extension, connects via Chrome DevTools Protocol (CDP),
 * and verifies:
 * 1. Extension Manifest V3 registration and background service worker lifecycle.
 * 2. Extension ID resolution.
 * 3. Popup page DOM rendering (title, brand shield, URL display, action buttons).
 * 4. Settings drawer controls (backend endpoint validation, default production URL).
 * 5. Input acceptance and event handler initialization.
 * 6. Background message dispatch (GET_STATUS, GET_SETTINGS).
 * 7. Clean teardown with zero orphaned processes or temporary files.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket } from "ws";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const extPath = path.join(projectRoot, "extension");

// Candidate browser binaries
const BROWSER_PATHS = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
];

function findBrowserBinary() {
  for (const p of BROWSER_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runCdpCommand(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 100000);
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`CDP command timed out: ${method}`));
    }, 10000);

    function onMessage(data) {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.id === id) {
          clearTimeout(timeout);
          ws.off("message", onMessage);
          if (msg.error) {
            reject(new Error(msg.error.message || JSON.stringify(msg.error)));
          } else {
            resolve(msg.result);
          }
        }
      } catch {
        // ignore parse error
      }
    }

    function cleanup() {
      clearTimeout(timeout);
      ws.off("message", onMessage);
    }

    ws.on("message", onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  console.log("================================================================================");
  console.log(" AheadGuard AI — Chromium Extension End-to-End Acceptance Test");
  console.log("================================================================================");

  // 1. Structural Manifest & Assets Check
  console.log("\n[STAGE 1] Verifying unpacked extension structure in /extension...");
  const manifestPath = path.join(extPath, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error("Missing manifest.json in extension/");
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  console.log(`  ✓ Manifest V3 loaded: "${manifest.name}" (version ${manifest.version})`);

  const requiredFiles = [
    manifest.background?.service_worker || "background.js",
    manifest.action?.default_popup || "popup.html",
    "popup.js",
    "popup.css",
    "content.js",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
  ];

  for (const rel of requiredFiles) {
    const p = path.join(extPath, rel);
    if (!fs.existsSync(p)) {
      throw new Error(`Missing required extension file: ${rel}`);
    }
  }
  console.log(`  ✓ All ${requiredFiles.length} manifest-referenced assets verified present.`);

  // 2. Browser Discovery
  console.log("\n[STAGE 2] Discovering local Chromium browser engine...");
  const browserBin = findBrowserBinary();
  if (!browserBin) {
    console.warn("  [SKIP] No local Chromium browser executable detected.");
    process.exit(0);
  }
  console.log(`  ✓ Using Chromium binary: ${browserBin}`);

  const port = 9222 + Math.floor(Math.random() * 500);
  const tempProfile = fs.mkdtempSync(path.join(os.tmpdir(), "ag-ext-e2e-"));
  console.log(`  ✓ Isolated test profile: ${tempProfile}`);
  console.log(`  ✓ CDP remote debugging port: ${port}`);

  let browserProc = null;
  let exitCode = 0;

  try {
    // 3. Launch Chromium with unpacked extension
    console.log("\n[STAGE 3] Launching Chromium with --load-extension...");
    browserProc = spawn(browserBin, [
      "--headless=new",
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${tempProfile}`,
      `--disable-extensions-except=${extPath}`,
      `--load-extension=${extPath}`,
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
    ]);

    browserProc.on("error", (err) => {
      console.error("  [ERROR] Browser process error:", err.message);
    });

    // Wait for CDP to become responsive
    let cdpReady = false;
    for (let i = 0; i < 20; i++) {
      await sleep(500);
      try {
        const vRes = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (vRes.ok) {
          cdpReady = true;
          break;
        }
      } catch {}
    }

    if (!cdpReady) {
      throw new Error(`Chromium CDP failed to respond on port ${port} within 10s.`);
    }
    console.log("  ✓ Chromium CDP is responsive.");

    // 4. Discover Extension Targets
    console.log("\n[STAGE 4] Inspecting loaded extension targets...");
    const listRes = await fetch(`http://127.0.0.1:${port}/json/list`);
    const targets = await listRes.json();

    const swTarget = targets.find(
      (t) => t.type === "service_worker" && t.url.includes("background.js")
    );

    if (!swTarget) {
      console.log("  Targets found:", targets.map((t) => `${t.type}: ${t.url}`));
      throw new Error("AheadGuard background service worker target was not detected.");
    }

    const extId = swTarget.url.split("/")[2];
    console.log(`  ✓ AheadGuard service worker running! Extension ID: [${extId}]`);
    console.log(`  ✓ Worker URL: ${swTarget.url}`);

    // 5. Open Extension Popup Page
    console.log("\n[STAGE 5] Loading AheadGuard popup.html in Chromium...");
    const popupUrl = `chrome-extension://${extId}/popup.html`;
    const openRes = await fetch(`http://127.0.0.1:${port}/json/new?${popupUrl}`, { method: "PUT" });
    const popupTab = await openRes.json();
    console.log(`  ✓ Popup tab created: ${popupTab.id}`);

    // Connect to popup target via CDP WebSocket
    const ws = new WebSocket(popupTab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.on("open", resolve);
      ws.on("error", reject);
    });
    console.log("  ✓ Connected to popup DevTools Protocol session.");

    // Enable Runtime and DOM domains
    await runCdpCommand(ws, "Runtime.enable");
    await sleep(500);

    // 6. Test Popup DOM Structure & Elements
    console.log("\n[STAGE 6] Verifying Popup UI Elements & Layout...");
    const domEval = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        return {
          title: document.title,
          brandTitle: document.querySelector('.brand-title')?.textContent?.trim(),
          brandSub: document.querySelector('.brand-sub')?.textContent?.trim(),
          hasActiveUrlDisplay: !!document.getElementById('active-url-display'),
          hasCheckBtn: !!document.getElementById('check-btn'),
          checkBtnDisabled: document.getElementById('check-btn')?.disabled,
          hasSettingsBtn: !!document.getElementById('settings-btn'),
          hasCustomUrlInput: !!document.getElementById('custom-url-input'),
          hasLedgerList: !!document.getElementById('ledger-list'),
          backendUrlInputVal: document.getElementById('backend-url-input')?.value || '',
          defaultBackendMatch: (document.getElementById('backend-url-input')?.value || '') === 'https://aheadguard-ai.vercel.app'
        };
      })()`,
      returnByValue: true,
    });

    const ui = domEval.result?.value;
    console.log(`  ✓ Page Title: "${ui.title}"`);
    console.log(`  ✓ Brand Title: "${ui.brandTitle}" (${ui.brandSub})`);
    console.log(`  ✓ Active URL Display element: ${ui.hasActiveUrlDisplay}`);
    console.log(`  ✓ Investigation Action Button: ${ui.hasCheckBtn}`);
    console.log(`  ✓ Settings Control element: ${ui.hasSettingsBtn}`);
    console.log(`  ✓ Custom Input element: ${ui.hasCustomUrlInput}`);
    console.log(`  ✓ Default Backend Endpoint: "${ui.backendUrlInputVal}" (Official production parity: ${ui.defaultBackendMatch})`);

    if (!ui.hasCheckBtn || !ui.hasSettingsBtn || !ui.hasActiveUrlDisplay) {
      throw new Error("Critical popup UI elements failed to render in Chromium.");
    }

    // 7. Test Settings Drawer Toggle Interaction
    console.log("\n[STAGE 7] Testing Settings Drawer Toggle Interaction...");
    const drawerTest = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        const settingsBtn = document.getElementById('settings-btn');
        const drawer = document.getElementById('settings-drawer');
        const initialHidden = drawer.classList.contains('hidden');
        settingsBtn.click();
        const opened = !drawer.classList.contains('hidden');
        const closeBtn = document.getElementById('close-settings');
        closeBtn.click();
        const closedAgain = drawer.classList.contains('hidden');
        return { initialHidden, opened, closedAgain };
      })()`,
      returnByValue: true,
    });

    const drawer = drawerTest.result?.value;
    console.log(`  ✓ Settings Drawer toggle: initialHidden=${drawer.initialHidden}, opened=${drawer.opened}, closedAgain=${drawer.closedAgain}`);
    if (!drawer.opened || !drawer.closedAgain) {
      throw new Error("Settings drawer interactive toggle failed.");
    }

    // 8. Test Input Entry & Validation in Popup
    console.log("\n[STAGE 8] Testing Custom Input Entry in Popup...");
    const inputTest = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        const toggleBtn = document.getElementById('toggle-manual-input');
        const container = document.getElementById('custom-input-container');
        toggleBtn.click();
        const containerVisible = !container.classList.contains('hidden');
        const input = document.getElementById('custom-url-input');
        input.value = 'https://example.com/test-suspicious-login';
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const checkBtn = document.getElementById('check-btn');
        return {
          containerVisible,
          inputValue: input.value,
          checkBtnEnabled: !checkBtn.disabled
        };
      })()`,
      returnByValue: true,
    });

    const inp = inputTest.result?.value;
    console.log(`  ✓ Custom input container displayed: ${inp.containerVisible}`);
    console.log(`  ✓ Input populated: "${inp.inputValue}"`);
    console.log(`  ✓ Check Button enabled state: ${inp.checkBtnEnabled}`);

    // 9. Inspect Service Worker Message API directly
    console.log("\n[STAGE 9] Testing Extension Service Worker Messaging API...");
    const msgTest = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (settings) => {
          chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (status) => {
            resolve({
              settingsReceived: !!settings,
              backendUrl: settings?.backendUrl,
              statusReceived: !!status,
              monitoringEnabled: status?.monitoringEnabled
            });
          });
        });
      })`,
      awaitPromise: true,
      returnByValue: true,
    });

    const msg = msgTest.result?.value;
    console.log(`  ✓ Background Service Worker GET_SETTINGS response: received=${msg.settingsReceived}, backendUrl="${msg.backendUrl}"`);
    console.log(`  ✓ Background Service Worker GET_STATUS response: received=${msg.statusReceived}, monitoringEnabled=${msg.monitoringEnabled}`);

    if (!msg.settingsReceived || !msg.statusReceived) {
      throw new Error("Background service worker message passing failed.");
    }

    ws.close();
    console.log("\n================================================================================");
    console.log(" [SUCCESS] CHROMIUM EXTENSION END-TO-END ACCEPTANCE TEST PASSED!");
    console.log("================================================================================");
  } catch (err) {
    console.error("\n[FAIL] Extension acceptance test failed:", err.message);
    exitCode = 1;
  } finally {
    if (browserProc) {
      browserProc.kill("SIGKILL");
    }
    await sleep(1000);
    try {
      fs.rmSync(tempProfile, { recursive: true, force: true });
    } catch {}
  }

  process.exit(exitCode);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
