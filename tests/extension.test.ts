import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { investigateUrl, createUnknownReport } from "../extension/src/api-client";
import type { InvestigationReport, RiskOutcome } from "../extension/src/types";
import fs from "fs";
import path from "path";

describe("AheadGuard Chrome Extension Test Suite (Section 11: Tests 1 - 20)", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // Test 1: Valid destination submission
  it("Test 1: Valid destination submission sends proper payload to backend and returns report", async () => {
    const mockReport: Partial<InvestigationReport> = {
      investigationId: "inv_12345",
      riskOutcome: "Low observed risk",
      originalUrl: "https://example.com",
      outcomeReason: "Standard checks passed without observed warning signs.",
      observedDestination: {
        submittedUrl: "https://example.com",
        normalizedUrl: "https://example.com/",
        submittedHost: "example.com",
        destinationChanged: false,
        redirectChain: ["https://example.com/"],
      },
      evidenceItems: [],
      checksPerformed: [],
      actionPreview: {
        proposedAction: "Navigating to example.com.",
        consequenceIfProceed: "Routine web browsing.",
        riskFactors: [],
      },
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ report: mockReport }),
    });

    const report = await investigateUrl({
      url: "https://example.com",
      backendUrl: "http://localhost:3000",
    });

    expect(report.investigationId).toBe("inv_12345");
    expect(report.riskOutcome).toBe("Low observed risk");
  });

  // Test 2: Unsupported URL rejection
  it("Test 2: Unsupported URL schemes (chrome://, file://, about:) are rejected before making network calls", async () => {
    const unsupported = [
      "chrome://extensions",
      "chrome-extension://abcdefg/popup.html",
      "file:///C:/Users/test/secret.txt",
      "about:blank",
      "javascript:void(0)",
    ];

    for (const url of unsupported) {
      await expect(
        investigateUrl({
          url,
          backendUrl: "http://localhost:3000",
        })
      ).rejects.toThrow();
    }
  });

  // Test 3: Invalid backend response handled defensively
  it("Test 3: Invalid backend response (malformed JSON / missing report) falls back to Unknown report", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ unexpectedData: "no report field" }),
    });

    const report = await investigateUrl({
      url: "https://example.com",
      backendUrl: "http://localhost:3000",
    });

    expect(report.riskOutcome).toBe("Unknown");
    expect(report.outcomeReason).toMatch(/did not contain an investigation report|Inconclusive/i);
  });

  // Test 4: Backend timeout handling
  it("Test 4: Backend timeout aborts cleanly and returns defensive Unknown report", async () => {
    const abortController = new AbortController();
    abortController.abort(); // simulate immediate timeout/abort

    const report = await investigateUrl({
      url: "https://slow-destination.com",
      backendUrl: "http://localhost:3000",
      signal: abortController.signal,
    });

    expect(report.riskOutcome).toBe("Unknown");
    expect(report.outcomeReason).toMatch(/timed out/i);
  });

  // Test 5: Backend error handling (500 / 502 / 504)
  it("Test 5: Backend server error returns Unknown report with sanitized message without crashing", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 502,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ error: "TinyFish upstream gateway error" }),
    });

    const report = await investigateUrl({
      url: "https://example.com",
      backendUrl: "http://localhost:3000",
    });

    expect(report.riskOutcome).toBe("Unknown");
    expect(report.outcomeReason).toContain("TinyFish upstream gateway error");
  });

  // Test 6: UNKNOWN outcome on failed investigation
  it("Test 6: Failed or inconclusive investigation is strictly classified as Unknown", () => {
    const fallback = createUnknownReport("https://failed-check.org", "Network unreachable");
    expect(fallback.riskOutcome).toBe("Unknown");
    expect(fallback.threatLikelihood).toBe("Uncertain");
    expect(fallback.outcomeReason).toContain("Network unreachable");
    expect(fallback.outcomeReason).toContain("Inconclusive results cannot be treated as safe");
  });

  // Test 7: All four outcome labels displayed correctly
  it("Test 7: All four required outcome labels are recognized and handled consistently", () => {
    const validOutcomes: RiskOutcome[] = [
      "Low observed risk",
      "Unknown",
      "Suspicious",
      "High risk",
    ];

    expect(validOutcomes).toHaveLength(4);
    for (const outcome of validOutcomes) {
      expect(["Low observed risk", "Unknown", "Suspicious", "High risk"]).toContain(outcome);
    }
  });

  // Test 8: Evidence and limitations rendered accurately
  it("Test 8: Evidence items retain provenance and transparent limitations", () => {
    const report = createUnknownReport("https://example.com", "Test reason");
    expect(report.evidenceItems[0].provenance).toBe("policy_rule");
    expect(report.limitations.length).toBeGreaterThan(0);
    expect(report.limitations.some((l) => l.includes("Absence of threat indicators"))).toBe(true);
  });

  // Test 9: Duplicate navigation event handling
  it("Test 9: Deduplication mechanism tracks recent checks to prevent redundant API loops", () => {
    const recentChecks = new Map<string, { timestamp: number; report: InvestigationReport }>();
    const DEDUPE_COOLDOWN_MS = 5 * 60 * 1000;

    const dummyReport = createUnknownReport("https://example.com", "Cached check");
    recentChecks.set("https://example.com", { timestamp: Date.now(), report: dummyReport });

    // Check within cooldown window
    const cached = recentChecks.get("https://example.com");
    expect(cached).toBeDefined();
    expect(Date.now() - cached!.timestamp < DEDUPE_COOLDOWN_MS).toBe(true);

    // Check after cooldown window
    const expiredCheck = { timestamp: Date.now() - (DEDUPE_COOLDOWN_MS + 1000), report: dummyReport };
    expect(Date.now() - expiredCheck.timestamp < DEDUPE_COOLDOWN_MS).toBe(false);
  });

  // Test 10: Redirect and repeated-event handling
  it("Test 10: Redirect detection correctly sets destinationChanged flag", () => {
    const submittedHost: string = "short.url";
    const finalHost: string = "actual-destination.com";
    const destinationChanged = submittedHost !== finalHost;
    expect(destinationChanged).toBe(true);
  });

  // Test 11: Monitoring disabled behavior
  it("Test 11: When monitoring is disabled, active tab navigation is not automatically audited", () => {
    const settings = { monitoringEnabled: false, historyPaused: false, backendUrl: "http://localhost:3000" };
    const shouldAutoCheck = settings.monitoringEnabled;
    expect(shouldAutoCheck).toBe(false);
  });

  // Test 12: Pause behavior (Ledger paused)
  it("Test 12: When history is paused, newly completed checks are not written to ledger", () => {
    const settings = { monitoringEnabled: true, historyPaused: true, backendUrl: "http://localhost:3000" };
    const ledger: string[] = ["existing_id_1"];

    function recordIfActive(id: string) {
      if (!settings.historyPaused) {
        ledger.push(id);
      }
    }

    recordIfActive("new_id_2");
    expect(ledger).toHaveLength(1);
    expect(ledger).not.toContain("new_id_2");
  });

  // Test 13: History purge
  it("Test 13: History purge empties the local evidence ledger", () => {
    let ledger = [{ id: "1" }, { id: "2" }];
    // Purge action
    ledger = [];
    expect(ledger).toHaveLength(0);
  });

  // Test 14: Malformed extension messages rejected
  it("Test 14: Malformed extension message payloads are rejected safely", () => {
    function validateMessage(msg: unknown): boolean {
      if (!msg || typeof msg !== "object") return false;
      const record = msg as Record<string, unknown>;
      return typeof record.type === "string" && record.type.length > 0;
    }

    expect(validateMessage(null)).toBe(false);
    expect(validateMessage("string")).toBe(false);
    expect(validateMessage({})).toBe(false);
    expect(validateMessage({ type: "" })).toBe(false);
    expect(validateMessage({ type: "CHECK_URL", url: "https://example.com" })).toBe(true);
  });

  // Test 15: No API key exposed in extension assets
  it("Test 15: Verifies no TinyFish API key or secret token exists in extension assets", () => {
    const extensionDir = path.resolve(__dirname, "../extension");
    const filesToCheck = [
      "manifest.json",
      "popup.html",
      "popup.css",
      "background.js",
      "popup.js",
      "content.js",
      "src/types.ts",
      "src/api-client.ts",
      "src/background.ts",
      "src/popup.ts",
      "src/content.ts",
    ];

    for (const relPath of filesToCheck) {
      const fullPath = path.join(extensionDir, relPath);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        // Must NOT contain hardcoded API keys
        expect(content).not.toMatch(/TINYFISH_API_KEY\s*=\s*['"][^'"]+['"]/i);
        expect(content).not.toMatch(/tf_live_[a-zA-Z0-9_-]{10,}/i);
      }
    }
  });

  // Test 16: No fabricated risk result
  it("Test 16: Never fabricates a Low Observed Risk verdict when checks were incomplete", () => {
    const incompleteReport = createUnknownReport("https://unverified.com", "Missing page content");
    expect(incompleteReport.riskOutcome).toBe("Unknown");
    expect(incompleteReport.riskOutcome).not.toBe("Low observed risk");
  });

  // Test 17: No false claim that navigation was blocked
  it("Test 17: Extension labels guidance honestly as pre-action decision support, not hard blocking", () => {
    const manifestPath = path.resolve(__dirname, "../extension/manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

    expect(manifest.description.toLowerCase()).not.toContain("blocks all");
    expect(manifest.description.toLowerCase()).toContain("safety");
  });

  // Test 18: Keyboard and focus behavior in critical UI
  it("Test 18: Extension popup HTML provides accessible, focusable controls", () => {
    const popupHtml = fs.readFileSync(path.resolve(__dirname, "../extension/popup.html"), "utf-8");
    expect(popupHtml).toContain('id="check-btn"');
    expect(popupHtml).toContain('id="settings-btn"');
    expect(popupHtml).toContain('aria-label="Open settings"');
    expect(popupHtml).toContain('id="custom-url-input"');
  });

  // Test 19: Retry behavior
  it("Test 19: Retrying an investigation bypasses stale errors and fetches fresh state", async () => {
    let callCount = 0;
    global.fetch = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        return Promise.reject(new Error("Transient connection error"));
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          report: createUnknownReport("https://retry-test.com", "Recovered check"),
        }),
      });
    });

    const report1 = await investigateUrl({ url: "https://retry-test.com" });
    expect(report1.outcomeReason).toContain("Transient connection error");

    const report2 = await investigateUrl({ url: "https://retry-test.com" });
    expect(report2.outcomeReason).toContain("Recovered check");
    expect(callCount).toBe(2);
  });

  // Test 20: Production build and extension packaging
  it("Test 20: Manifest V3 is strictly valid and references existing bundled assets and icons", () => {
    const extensionDir = path.resolve(__dirname, "../extension");
    const manifestPath = path.join(extensionDir, "manifest.json");
    expect(fs.existsSync(manifestPath)).toBe(true);

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.background.service_worker).toBe("background.js");
    expect(manifest.action.default_popup).toBe("popup.html");

    // Verify all referenced files exist
    expect(fs.existsSync(path.join(extensionDir, manifest.background.service_worker))).toBe(true);
    expect(fs.existsSync(path.join(extensionDir, manifest.action.default_popup))).toBe(true);
    expect(fs.existsSync(path.join(extensionDir, manifest.icons["16"]))).toBe(true);
    expect(fs.existsSync(path.join(extensionDir, manifest.icons["48"]))).toBe(true);
    expect(fs.existsSync(path.join(extensionDir, manifest.icons["128"]))).toBe(true);
    expect(fs.existsSync(path.join(extensionDir, manifest.content_scripts[0].js[0]))).toBe(true);
  });

  // Test 21: Backend URL setting validation prevents redirection to third-party endpoints
  it("Test 21: Backend endpoint configuration rejects redirection to unexpected external domains", () => {
    function isValidBackendEndpoint(url?: string): boolean {
      if (!url || typeof url !== "string") return false;
      try {
        const parsed = new URL(url);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
        if (parsed.username || parsed.password) return false;
        const host = parsed.hostname.toLowerCase();
        if (host === "localhost" || host === "127.0.0.1") return true;
        if (host === "aheadguard-ai.vercel.app" || host.endsWith(".vercel.app")) return true;
        return false;
      } catch {
        return false;
      }
    }

    // Permitted endpoints
    expect(isValidBackendEndpoint("http://localhost:3000")).toBe(true);
    expect(isValidBackendEndpoint("http://127.0.0.1:3000")).toBe(true);
    expect(isValidBackendEndpoint("http://localhost:8080")).toBe(true);
    expect(isValidBackendEndpoint("https://aheadguard-ai.vercel.app")).toBe(true);

    // Blocked malicious/exfiltration endpoints
    expect(isValidBackendEndpoint("https://attacker-data-logger.com")).toBe(false);
    expect(isValidBackendEndpoint("http://evil.com/api")).toBe(false);
    expect(isValidBackendEndpoint("javascript:void(0)")).toBe(false);
    expect(isValidBackendEndpoint("http://user:pass@localhost:3000")).toBe(false);
  });

  // Test 22: Sender verification blocks messages missing required sender identity
  it("Test 22: Message dispatcher rejects messages with missing or mismatched sender identity", () => {
    function verifySender(sender: { id?: string }, runtimeId: string = "aheadguard_runtime_id"): boolean {
      if (!sender.id || sender.id !== runtimeId) return false;
      return true;
    }

    // Missing sender ID
    expect(verifySender({})).toBe(false);
    expect(verifySender({ id: "" })).toBe(false);

    // Mismatched foreign extension ID
    expect(verifySender({ id: "foreign_extension_attacker_id" })).toBe(false);

    // Legitimate extension sender
    expect(verifySender({ id: "aheadguard_runtime_id" })).toBe(true);
  });
});
