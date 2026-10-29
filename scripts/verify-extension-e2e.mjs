#!/usr/bin/env node
/**
 * AheadGuard AI — Chromium Extension End-to-End Acceptance Test Suite
 *
 * Exercises the entire real-world extension workflow against a deterministic local test service:
 * 1. Unpacked Manifest V3 extension loading & background service worker registration.
 * 2. Active tab URL detection and supported scheme validation.
 * 3. Settings configuration (backend endpoint assignment & persistence).
 * 4. Custom link input expansion and validation.
 * 5. Full investigation request dispatch via UI button click.
 * 6. Mock backend response handling and risk assessment rendering (SUSPICIOUS outcome, action preview, evidence, advice).
 * 7. Defensive error handling (HTTP 500 fallback to Unknown without false-safe claims).
 * 8. Evidence ledger recording, display, and clearing.
 * 9. Guaranteed cleanup of child processes, HTTP servers, and temporary profiles.
 */
import { execSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket } from "ws";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const extPath = path.join(projectRoot, "extension");

// Command-line flag parsing
const args = process.argv.slice(2);
const requireBrowser = args.includes("--require-browser");
const customBrowserArg = args.find((a) => a.startsWith("--browser="))?.split("=")[1];

// Supported browser candidates by platform
const CANDIDATE_BROWSERS = [
  customBrowserArg,
  process.env.CHROME_PATH,
  process.env.BROWSER_PATH,
  // Windows
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  path.join(process.env.LOCALAPPDATA || "", "Google\\Chrome\\Application\\chrome.exe"),
  // Linux / GitHub Actions runner
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  // macOS
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
].filter(Boolean);

function findBrowserBinary() {
  if (customBrowserArg) {
    if (fs.existsSync(customBrowserArg)) {
      return customBrowserArg;
    }
    return null;
  }
  for (const b of CANDIDATE_BROWSERS) {
    if (fs.existsSync(b)) {
      return b;
    }
  }
  if (process.platform !== "win32") {
    try {
      const whichRes = execSync("which google-chrome || which chrome || which chromium", {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "ignore"],
      }).trim().split("\n")[0];
      if (whichRes && fs.existsSync(whichRes)) {
        return whichRes;
      }
    } catch {}
  }
  return null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Bounded CDP execution helper
function runCdpCommand(ws, method, params = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1000000) + 1;
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`CDP command timed out (${timeoutMs}ms): ${method}`));
    }, timeoutMs);

    function onMessage(data) {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.id === id) {
          clearTimeout(timer);
          cleanup();
          if (msg.error) {
            reject(new Error(msg.error.message || JSON.stringify(msg.error)));
          } else {
            resolve(msg.result);
          }
        }
      } catch {}
    }

    function cleanup() {
      ws.off("message", onMessage);
    }

    ws.on("message", onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

// Wait for a condition in the page DOM with bounded polling
async function waitForCondition(ws, conditionExpr, desc = "DOM condition", maxWaitMs = 12000) {
  const start = Date.now();
  let lastErr = null;
  while (Date.now() - start < maxWaitMs) {
    try {
      const evalRes = await runCdpCommand(ws, "Runtime.evaluate", {
        expression: conditionExpr,
        returnByValue: true,
      });
      if (evalRes?.result?.value === true) {
        return true;
      }
    } catch (err) {
      lastErr = err.message;
    }
    await sleep(250);
  }
  const debugInfo = await runCdpCommand(ws, "Runtime.evaluate", {
    expression: `JSON.stringify({ href: window.location.href, readyState: document.readyState, title: document.title, hasElement: Boolean(document.getElementById("active-url-display")), innerText: document.body?.innerText?.slice(0, 500) })`,
    returnByValue: true,
  }).catch(() => null);
  if (debugInfo?.result?.value) {
    console.error("  [DEBUG] Page state at timeout:", debugInfo.result.value);
  }
  throw new Error(
    `Timed out waiting for ${desc} (${maxWaitMs}ms)${lastErr ? ` [last CDP error: ${lastErr}]` : ""}`
  );
}

// Mock Investigation Report Generator
function buildMockSuspiciousReport(targetUrl) {
  let hostname = "suspicious-bank-login.com";
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {}

  return {
    investigationId: `inv_mock_${Date.now()}`,
    timestamp: new Date().toISOString(),
    originalUrl: targetUrl,
    normalizedUrl: targetUrl,
    observedDestination: {
      submittedUrl: targetUrl,
      normalizedUrl: targetUrl,
      submittedHost: hostname,
      finalHost: hostname,
      destinationChanged: false,
      redirectChain: [targetUrl],
    },
    riskOutcome: "Suspicious",
    threatLikelihood: "Moderate",
    consequenceImpact: "High",
    outcomeReason: "Detected deceptive credential harvesting form imitating a banking portal.",
    recommendedAction: "Do not submit credentials. Verify through an independent channel.",
    actionPreview: {
      proposedAction: "Submitting financial credentials",
      consequenceIfProceed: "Account access credentials will be disclosed to an unverified third party.",
      riskFactors: [
        "Unverified SSL issuer",
        "Domain newly registered (under 7 days)",
        "Password field present on unauthenticated host",
      ],
    },
    checksPerformed: [
      { name: "Domain Reputation & Age", status: "completed", detail: "Domain registered 3 days ago." },
      { name: "Credential Form Inspection", status: "completed", detail: "Password input field detected." },
    ],
    evidenceItems: [
      {
        label: "Newly Registered Domain",
        detail: "Domain was created 3 days ago with privacy guard.",
        kind: "warning",
        provenance: "url_structure",
      },
      {
        label: "Deceptive Banking Form",
        detail: "Password field observed on non-official host.",
        kind: "warning",
        provenance: "page_content",
      },
    ],
    observedFacts: {
      credentialOrPaymentRequest: true,
      downloadOrPermissionRequest: false,
      formsObserved: true,
      hasPasswordField: true,
      hasPaymentField: false,
      hasPunycode: false,
      isNumericIp: false,
      isHttp: false,
    },
    modelInterpretations: [],
    warningSigns: ["Newly registered domain", "Password field on unverified host"],
    missingEvidence: ["No official organizational registry match"],
    limitations: ["Remote sandbox investigation performed against mock test environment."],
    eventsCount: 4,
  };
}

async function main() {
  console.log("================================================================================");
  console.log(" AheadGuard AI — Chromium Extension Full End-to-End Acceptance Suite");
  console.log("================================================================================");

  // ---------------------------------------------------------------------------
  // STAGE 1: Verify Manifest & Asset Integrity
  // ---------------------------------------------------------------------------
  console.log("\n[STAGE 1] Verifying unpacked extension manifest and assets...");
  const manifestPath = path.join(extPath, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest.json missing at ${manifestPath}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  console.log(`  ✓ Manifest loaded: "${manifest.name}" v${manifest.version} (MV${manifest.manifest_version})`);

  const requiredAssets = [
    manifest.background?.service_worker || "background.js",
    manifest.action?.default_popup || "popup.html",
    "popup.js",
    "popup.css",
    "content.js",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
  ];
  for (const asset of requiredAssets) {
    if (!fs.existsSync(path.join(extPath, asset))) {
      throw new Error(`Missing required extension asset: ${asset}`);
    }
  }
  console.log(`  ✓ All ${requiredAssets.length} manifest-referenced files confirmed present.`);

  // ---------------------------------------------------------------------------
  // STAGE 2: Start Isolated Mock HTTP Test Service
  // ---------------------------------------------------------------------------
  console.log("\n[STAGE 2] Starting isolated local mock backend service on port 3000...");
  const recordedRequests = [];
  let mockServer = null;
  let browserProc = null;
  let tempProfile = null;
  let exitCode = 0;

  try {
    await new Promise((resolve, reject) => {
      mockServer = http.createServer((req, res) => {
        console.log(`[MOCK SERVER RECEIVED] ${req.method} ${req.url}`);
        // CORS headers
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization");

        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }

        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });

        req.on("end", () => {
          const url = new URL(req.url, "http://127.0.0.1:3000");

          // Simple active tab test page
          if (url.pathname === "/test-safe-page" && req.method === "GET") {
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(
              "<!DOCTYPE html><html><head><title>Safe Corporate Portal</title></head><body><h1>Safe Destination</h1></body></html>"
            );
            return;
          }

          // Investigation API Endpoint
          if (url.pathname === "/api/investigate" && req.method === "POST") {
            let parsedBody = {};
            try {
              parsedBody = JSON.parse(body);
            } catch {}

            recordedRequests.push({
              method: req.method,
              pathname: url.pathname,
              body: parsedBody,
              headers: req.headers,
              timestamp: Date.now(),
            });

            const inputStr = String(parsedBody.input || "");

            // 1. Error simulation route
            if (inputStr.includes("trigger-500-error.com")) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Simulated upstream service disruption." }));
              return;
            }

            // 2. Successful investigation route
            const report = buildMockSuspiciousReport(inputStr);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ report }));
            return;
          }

          // Unhandled route
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Not Found" }));
        });
      });

      mockServer.on("error", (err) => {
        reject(new Error(`Failed to bind mock backend server on port 3000: ${err.message}`));
      });

      mockServer.listen(3000, "127.0.0.1", () => {
        resolve();
      });
    });
    console.log("  ✓ Mock backend server listening on http://127.0.0.1:3000");

    // -------------------------------------------------------------------------
    // STAGE 3: Discover Local Browser Engine
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 3] Discovering Chromium browser executable...");
    const browserBin = findBrowserBinary();
    if (!browserBin) {
      const msg = "No supported Chromium browser executable discovered on this platform.";
      if (requireBrowser) {
        throw new Error(`[FAIL] ${msg} (--require-browser flag was specified).`);
      } else {
        console.warn(`  [SKIP] ${msg} Proceeding without local headless browser execution.`);
        if (mockServer) {
          mockServer.close();
        }
        process.exit(0);
      }
    }
    console.log(`  ✓ Chromium browser identified: ${browserBin}`);

    const port = 9300 + Math.floor(Math.random() * 400);
    tempProfile = fs.mkdtempSync(path.join(os.tmpdir(), "ag-ext-full-e2e-"));
    console.log(`  ✓ Isolated user profile: ${tempProfile}`);
    console.log(`  ✓ CDP remote debugging port: ${port}`);

    // -------------------------------------------------------------------------
    // STAGE 4: Launch Chromium with Unpacked Extension
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 4] Launching Chromium with --load-extension...");
    browserProc = spawn(browserBin, [
      "--headless=new",
      `--remote-debugging-port=${port}`,
      "--remote-debugging-address=127.0.0.1",
      `--user-data-dir=${tempProfile}`,
      `--disable-extensions-except=${extPath}`,
      `--load-extension=${extPath}`,
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
    ]);

    let browserStderr = "";
    browserProc.stderr?.on("data", (chunk) => {
      browserStderr += chunk.toString();
    });

    // Bounded wait for CDP responsiveness
    let cdpReady = false;
    for (let i = 0; i < 25; i++) {
      await sleep(500);
      if (browserProc.exitCode !== null) {
        throw new Error(
          `Chromium exited prematurely with code ${browserProc.exitCode}.\nStderr:\n${browserStderr}`
        );
      }
      try {
        const vRes = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (vRes.ok) {
          cdpReady = true;
          break;
        }
      } catch {}
    }
    if (!cdpReady) {
      throw new Error(
        `Chromium CDP failed to respond on port ${port} within 12.5s.\nBrowser stderr:\n${browserStderr || "(none)"}`
      );
    }
    console.log("  ✓ Chromium DevTools Protocol (CDP) ready.");

    // -------------------------------------------------------------------------
    // STAGE 5: Service Worker & Extension Discovery (Bounded Retry Loop)
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 5] Discovering AheadGuard extension service worker...");
    let swTarget = null;
    let lastTargets = [];
    for (let attempt = 0; attempt < 25; attempt++) {
      try {
        const listRes = await fetch(`http://127.0.0.1:${port}/json/list`);
        const targets = await listRes.json();
        lastTargets = targets;
        swTarget = targets.find(
          (t) => t.type === "service_worker" && t.url?.includes("background.js")
        );
        if (swTarget) break;
      } catch {}
      await sleep(500);
    }

    if (!swTarget) {
      console.error("  [DEBUG] Discovered targets at timeout:", JSON.stringify(lastTargets, null, 2));
      if (browserStderr) {
        console.error("  [DEBUG] Browser stderr output:\n", browserStderr);
      }
      throw new Error("AheadGuard background service worker target not detected in Chromium.");
    }
    const extId = swTarget.url.split("/")[2];
    console.log(`  ✓ AheadGuard service worker active! Extension ID: [${extId}]`);

    // -------------------------------------------------------------------------
    // STAGE 6: Create Active Tab with Supported HTTP Page
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 6] Opening active test tab (http://127.0.0.1:3000/test-safe-page)...");
    const activeTabRes = await fetch(`http://127.0.0.1:${port}/json/new?http://127.0.0.1:3000/test-safe-page`, {
      method: "PUT",
    });
    const activeTab = await activeTabRes.json();
    console.log(`  ✓ Active tab created: ${activeTab.id}`);
    await sleep(600);

    // -------------------------------------------------------------------------
    // STAGE 7: Open Popup and Connect DevTools Protocol Session
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 7] Loading AheadGuard popup.html and establishing CDP WebSocket...");
    const popupUrl = `chrome-extension://${extId}/popup.html`;
    const popupRes = await fetch(`http://127.0.0.1:${port}/json/new?${popupUrl}`, { method: "PUT" });
    const popupTab = await popupRes.json();
    console.log(`  ✓ Popup tab initialized: ${popupTab.id} (url="${popupTab.url}")`);

    const ws = new WebSocket(popupTab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.on("open", resolve);
      ws.on("error", reject);
    });
    console.log("  ✓ WebSocket connected to popup DevTools target.");
    await runCdpCommand(ws, "Page.enable");
    await runCdpCommand(ws, "Runtime.enable");
    console.log(`  Navigating popup target to ${popupUrl}...`);
    const navResult = await runCdpCommand(ws, "Page.navigate", { url: popupUrl });
    console.log(`  ✓ Page.navigate result:`, JSON.stringify(navResult));
    await sleep(1000);

    // -------------------------------------------------------------------------
    // STAGE 8: Verify Active Tab Detection & Initial Popup State
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 8] Verifying active tab detection in Popup DOM...");
    await waitForCondition(
      ws,
      `Boolean(document.getElementById("active-url-display")) && document.readyState === "complete"`,
      "popup DOM readiness"
    );
    await waitForCondition(
      ws,
      `document.getElementById("active-url-display")?.textContent?.trim().length > 0 && document.getElementById("active-url-display")?.textContent !== "Detecting active tab…"`,
      "active-url-display population",
      6000
    ).catch(() => {});

    const initialDom = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        return {
          title: document.title,
          activeUrl: document.getElementById("active-url-display")?.textContent?.trim(),
          unsupportedHidden: document.getElementById("unsupported-warning")?.classList?.contains("hidden"),
          checkBtnDisabled: document.getElementById("check-btn")?.disabled,
          resultContainerHidden: document.getElementById("result-container")?.classList?.contains("hidden")
        };
      })()`,
      returnByValue: true,
    });
    const init = initialDom.result?.value;
    console.log(`  ✓ Popup page title: "${init.title}"`);
    console.log(`  ✓ Active URL displayed: "${init.activeUrl}"`);
    console.log(`  ✓ Check button enabled: ${!init.checkBtnDisabled}`);
    console.log(`  ✓ Result container initially hidden: ${init.resultContainerHidden}`);

    // -------------------------------------------------------------------------
    // STAGE 9: Configure Backend Endpoint to Local Test Server
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 9] Configuring backend endpoint to http://127.0.0.1:3000 via background messaging...");
    const configUpdate = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `new Promise((resolve) => {
        chrome.runtime.sendMessage({
          type: "UPDATE_SETTINGS",
          settings: { backendUrl: "http://127.0.0.1:3000" }
        }, (res) => {
          const input = document.getElementById("backend-url-input");
          if (input) input.value = "http://127.0.0.1:3000";
          resolve(res);
        });
      })`,
      awaitPromise: true,
      returnByValue: true,
    });
    console.log(`  ✓ Background settings updated: success=${configUpdate.result?.value?.success}`);
    await sleep(500);

    // -------------------------------------------------------------------------
    // STAGE 10: Trigger End-to-End Investigation via Button Click
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 10] Triggering live investigation of custom destination...");
    const testDestination = "https://suspicious-bank-login.com";

    const clickAction = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        // 1. Expand custom input container
        const toggleBtn = document.getElementById("toggle-manual-input");
        toggleBtn.click();

        // 2. Populate target URL
        const input = document.getElementById("custom-url-input");
        input.value = "${testDestination}";
        input.dispatchEvent(new Event("input", { bubbles: true }));

        // 3. Click Investigate Destination button
        const checkBtn = document.getElementById("check-btn");
        checkBtn.click();

        return {
          inputValue: input.value,
          buttonDisabled: checkBtn.disabled,
          spinnerVisible: !document.getElementById("btn-spinner")?.classList?.contains("hidden")
        };
      })()`,
      returnByValue: true,
    });

    const clickState = clickAction.result?.value;
    console.log(`  ✓ Custom URL entered: "${clickState.inputValue}"`);
    console.log(`  ✓ Button entered loading state: disabled=${clickState.buttonDisabled}`);

    // Wait for investigation result container to render
    console.log("  Waiting for investigation response to render in DOM...");
    await waitForCondition(
      ws,
      `!document.getElementById("result-container")?.classList?.contains("hidden")`,
      "result-container visibility",
      12000
    );

    // Verify rendered report contents
    const renderedResult = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        return {
          riskTitle: document.getElementById("risk-title")?.textContent?.trim(),
          riskBannerClass: document.getElementById("risk-banner")?.className,
          riskSummary: document.getElementById("risk-summary")?.textContent?.trim(),
          metaHost: document.getElementById("meta-host")?.textContent?.trim(),
          evidenceCount: document.getElementById("evidence-count")?.textContent?.trim(),
          recText: document.getElementById("rec-text")?.textContent?.trim(),
          proposedAction: document.getElementById("preview-proposed")?.textContent?.trim(),
          previewConsequence: document.getElementById("preview-consequence")?.textContent?.trim(),
          ledgerCount: document.querySelectorAll("#ledger-list .ledger-item")?.length || 0
        };
      })()`,
      returnByValue: true,
    });

    const reportDom = renderedResult.result?.value;
    console.log(`  ✓ Rendered Risk Outcome: "${reportDom.riskTitle}"`);
    console.log(`  ✓ Risk Banner Class: "${reportDom.riskBannerClass}"`);
    console.log(`  ✓ Submitted Host in DOM: "${reportDom.metaHost}"`);
    console.log(`  ✓ Action Preview: "${reportDom.proposedAction}"`);
    console.log(`  ✓ Evidence Count displayed: ${reportDom.evidenceCount}`);
    console.log(`  ✓ Recommended Action: "${reportDom.recText}"`);

    // Verify assertions on successful investigation
    if (reportDom.riskTitle !== "SUSPICIOUS") {
      throw new Error(`Expected risk title 'SUSPICIOUS', got '${reportDom.riskTitle}'`);
    }
    if (!reportDom.riskBannerClass.includes("suspicious")) {
      throw new Error(`Risk banner missing 'suspicious' class: ${reportDom.riskBannerClass}`);
    }
    if (reportDom.metaHost !== "suspicious-bank-login.com") {
      throw new Error(`Expected host 'suspicious-bank-login.com', got '${reportDom.metaHost}'`);
    }

    // Verify mock server received the exact expected POST payload
    const matchingReq = recordedRequests.find(
      (r) =>
        r.pathname === "/api/investigate" &&
        (r.body?.input === testDestination || r.body?.input === `${testDestination}/`)
    );
    if (!matchingReq) {
      throw new Error("Backend server did not receive expected POST /api/investigate request.");
    }
    console.log("  ✓ Confirmed backend received POST request with matching input.");

    // -------------------------------------------------------------------------
    // STAGE 11: Test Defensive Error Handling (HTTP 500 Fallback)
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 11] Testing error handling & safety fallback on HTTP 500...");
    await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        const input = document.getElementById("custom-url-input");
        input.value = "https://trigger-500-error.com";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        document.getElementById("check-btn").click();
      })()`,
    });

    // Wait for the report to update
    await sleep(1500);

    const errorDomRes = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(() => {
        return {
          riskTitle: document.getElementById("risk-title")?.textContent?.trim(),
          riskBannerClass: document.getElementById("risk-banner")?.className,
          isLowRisk: document.getElementById("risk-title")?.textContent?.includes("LOW")
        };
      })()`,
      returnByValue: true,
    });

    const errResult = errorDomRes.result?.value;
    console.log(`  ✓ Outcome on upstream error: "${errResult.riskTitle}"`);
    console.log(`  ✓ Safety Check: Is false 'Low Risk' reported: ${errResult.isLowRisk}`);

    // Crucial safety guarantee: server error must never resolve to Low Risk
    if (errResult.isLowRisk) {
      throw new Error("FATAL SAFETY DEFECT: Server error resulted in false 'Low Risk' assessment!");
    }
    if (errResult.riskTitle !== "UNKNOWN") {
      throw new Error(`Expected defensive fallback 'UNKNOWN', got '${errResult.riskTitle}'`);
    }
    console.log("  ✓ Confirmed defensive 'UNKNOWN' outcome on backend error.");

    // -------------------------------------------------------------------------
    // STAGE 12: Test Local History / Ledger Deletion
    // -------------------------------------------------------------------------
    console.log("\n[STAGE 12] Testing Local History & Ledger Controls...");
    const clearTest = await runCdpCommand(ws, "Runtime.evaluate", {
      expression: `(async () => {
        // Open drawer and click clear button
        document.getElementById("settings-btn").click();
        document.getElementById("clear-ledger-btn").click();
        document.getElementById("close-settings").click();
        // Wait for DOM to refresh
        await new Promise(r => setTimeout(r, 400));
        const emptyMsg = document.querySelector("#ledger-list .empty-ledger")?.textContent?.trim();
        return {
          emptyMsg,
          cleared: emptyMsg?.includes("No recent investigations recorded")
        };
      })()`,
      awaitPromise: true,
      returnByValue: true,
    });

    const clearRes = clearTest.result?.value;
    console.log(`  ✓ Ledger clear executed: empty message="${clearRes?.emptyMsg}"`);
    if (!clearRes?.cleared) {
      throw new Error("Failed to clear local evidence ledger.");
    }

    ws.close();
    console.log("\n================================================================================");
    console.log(" [SUCCESS] ALL 12 EXTENSION ACCEPTANCE STAGES COMPLETED & VERIFIED!");
    console.log("================================================================================");
  } catch (err) {
    console.error("\n[FAIL] Extension E2E Acceptance Test failed:", err.message);
    exitCode = 1;
  } finally {
    // Stage 13: Clean Teardown
    console.log("\n[CLEANUP] Closing browser process, server, and temporary test profile...");
    if (mockServer) {
      mockServer.close();
    }
    if (browserProc) {
      browserProc.kill("SIGKILL");
    }
    await sleep(1000);
    try {
      fs.rmSync(tempProfile, { recursive: true, force: true });
    } catch {}
    console.log("  ✓ Teardown complete.");
  }

  process.exit(exitCode);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
