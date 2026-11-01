import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OPTIONS, POST, GET } from "../app/api/investigate/route";
import { isAllowedOrigin, normalizeOrigin, getAllowedOrigins, resetRateLimitForTesting } from "../lib/api-security";
import * as tinyfishModule from "../lib/tinyfish";
import * as dbModule from "../lib/db";

/**
 * AheadGuard AI — iOS & Mobile Compatibility Regression Test Suite
 *
 * NOTE: As required by Section 6, all mocked network and external dependencies
 * in this file are explicitly labeled as MOCKED TEST HARNESSES and are not
 * represented as live physical iPhone hardware probes.
 */

describe("iOS & Mobile Compatibility: CORS, Origin Normalization & Message Investigation", () => {
  const CANONICAL_ORIGIN = "https://aheadguard-ai.vercel.app";
  const TEST_IOS_WEBVIEW_ORIGIN = "capacitor://localhost";
  const TEST_CUSTOM_ORIGIN = "https://ios.aheadguard.internal";
  const APPROVED_EXTENSION_ID = "abcdefghijklmnopqrstuvwxyzabcdef";
  const originalEnv = { ...process.env };
  const originalFetch = global.fetch;

  beforeEach(() => {
    process.env.TINYFISH_API_KEY = "tf_mock_key_ios_test_suite_12345";
    process.env.ALLOWED_EXTENSION_IDS = APPROVED_EXTENSION_ID;
    delete process.env.ALLOWED_APP_ORIGINS;
    delete process.env.VERCEL_URL;
    resetRateLimitForTesting();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    global.fetch = originalFetch;
  });

  // =========================================================================
  // 1. ORIGIN NORMALIZATION & ALLOWLIST TESTS
  // =========================================================================

  it("[MOCKED] normalizeOrigin correctly normalizes schemes, ports, and trailing slashes", () => {
    expect(normalizeOrigin("https://aheadguard-ai.vercel.app/")).toBe("https://aheadguard-ai.vercel.app");
    expect(normalizeOrigin("https://aheadguard-ai.vercel.app:443")).toBe("https://aheadguard-ai.vercel.app");
    expect(normalizeOrigin("http://localhost:3000/")).toBe("http://localhost:3000");
    expect(normalizeOrigin("http://localhost:80")).toBe("http://localhost");
    expect(normalizeOrigin("capacitor://localhost/")).toBe("capacitor://localhost");
    expect(normalizeOrigin("ionic://localhost")).toBe("ionic://localhost");

    // Invalid & dangerous origins
    expect(normalizeOrigin("null")).toBeNull();
    expect(normalizeOrigin("*")).toBeNull();
    expect(normalizeOrigin("file:///var/mobile")).toBeNull();
    expect(normalizeOrigin("javascript:alert(1)")).toBeNull();
    expect(normalizeOrigin("data:text/html,test")).toBeNull();
  });

  it("[MOCKED] Canonical production origin is accepted across formatting variations", async () => {
    expect(isAllowedOrigin(CANONICAL_ORIGIN)).toBe(true);
    expect(isAllowedOrigin("https://aheadguard-ai.vercel.app/")).toBe(true);
    expect(isAllowedOrigin("https://aheadguard-ai.vercel.app:443")).toBe(true);

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "OPTIONS",
      headers: { Origin: CANONICAL_ORIGIN },
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(CANONICAL_ORIGIN);
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
    expect(res.headers.get("Access-Control-Allow-Headers")).toContain("Content-Type");
  });

  it("[MOCKED] Explicitly configured iOS/WebView origin via ALLOWED_APP_ORIGINS is accepted", async () => {
    process.env.ALLOWED_APP_ORIGINS = `${TEST_IOS_WEBVIEW_ORIGIN}, ${TEST_CUSTOM_ORIGIN}, https://preview.aheadguard.app/`;

    expect(isAllowedOrigin(TEST_IOS_WEBVIEW_ORIGIN)).toBe(true);
    expect(isAllowedOrigin(TEST_CUSTOM_ORIGIN)).toBe(true);
    expect(isAllowedOrigin("https://preview.aheadguard.app")).toBe(true);

    const req = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: TEST_IOS_WEBVIEW_ORIGIN },
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(TEST_IOS_WEBVIEW_ORIGIN);
  });

  it("[MOCKED] VERCEL_URL preview deployment origins are safely accepted", async () => {
    process.env.VERCEL_URL = "aheadguard-git-preview-fix-gokul1599.vercel.app";

    const previewOrigin = "https://aheadguard-git-preview-fix-gokul1599.vercel.app";
    expect(isAllowedOrigin(previewOrigin)).toBe(true);

    const req = new Request(`${previewOrigin}/api/investigate`, {
      method: "OPTIONS",
      headers: { Origin: previewOrigin },
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(previewOrigin);
  });

  it("[MOCKED] Unauthorized external origins receive HTTP 403 with diagnostic JSON body", async () => {
    const unauthorizedOrigins = [
      "https://attacker.com",
      "https://phishing-scam.net",
      "https://evil.vercel.app",
      "http://untrusted-host.org:8080",
    ];

    for (const origin of unauthorizedOrigins) {
      const optReq = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
        method: "OPTIONS",
        headers: { Origin: origin },
      });
      const optRes = await OPTIONS(optReq);
      expect(optRes.status).toBe(403);
      expect(optRes.headers.get("Access-Control-Allow-Origin")).toBeNull();

      const body = await optRes.json();
      expect(body.error).toContain("CORS origin not allowed");
      expect(body.code).toBe("CORS_ORIGIN_DENIED");
      expect(body.hint).toContain("ALLOWED_APP_ORIGINS");

      // Verify POST is also rejected with consistent 403
      const postReq = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
        method: "POST",
        headers: {
          Origin: origin,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ input: "https://example.com" }),
      });
      const postRes = await POST(postReq);
      expect(postRes.status).toBe(403);
      const postBody = await postRes.json();
      expect(postBody.error).toContain("CORS origin not allowed");
    }
  });

  it("[MOCKED] Arbitrary origin reflection is strictly rejected; never returns wildcard '*'", async () => {
    const maliciousOrigin = "https://spoofed.aheadguard-ai.vercel.app.attacker.com";
    const req = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: maliciousOrigin },
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(403);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(res.headers.get("Access-Control-Allow-Origin")).not.toBe("*");
    expect(res.headers.get("Access-Control-Allow-Origin")).not.toBe(maliciousOrigin);
  });

  it("[MOCKED] 'null' origin is strictly rejected", async () => {
    expect(isAllowedOrigin("null")).toBe(false);

    const req = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: "null" },
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(403);
  });

  it("[MOCKED] Missing Origin header on POST (same-origin / native share intent) proceeds safely", async () => {
    const req = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: "URGENT: Your account is suspended. Verify credentials immediately.",
        analysisMode: "message",
      }),
    });

    const res = await POST(req);
    // Should proceed to message intelligence (200 OK), NOT fail with CORS 403
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.report).toBeDefined();
    expect(body.report.analysisMode).toBe("message");
  });

  it("[MOCKED] Chrome Extension allowlist remains strictly enforced", async () => {
    const approved = `chrome-extension://${APPROVED_EXTENSION_ID}`;
    const unapproved = "chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

    expect(isAllowedOrigin(approved)).toBe(true);
    expect(isAllowedOrigin(unapproved)).toBe(false);
  });

  // =========================================================================
  // 2. MESSAGE INVESTIGATION SCENARIOS ON MOBILE / IOS
  // =========================================================================

  it("[MOCKED] Message investigation without URLs succeeds and detects scam indicators", async () => {
    const payload = {
      input: "Congratulations! You have been selected for Google Summer Internship 2026. Please send Rs 2500 laptop reservation deposit via GPay to recruiter99@okhdfcbank.",
      messageText: "Congratulations! You have been selected for Google Summer Internship 2026. Please send Rs 2500 laptop reservation deposit via GPay to recruiter99@okhdfcbank.",
      analysisMode: "message",
    };

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.report).toBeDefined();
    expect(["High risk", "Suspicious"]).toContain(data.report.riskOutcome);
    expect(data.report.offerIntegrity).toBeDefined();
    expect(data.report.offerIntegrity.safeActionPlan).toBeDefined();
    // Verify core trust principle is intact
    expect(data.report.offerIntegrity.safeActionPlan.primaryWarning).toContain("DO NOT PAY");
  });

  it("[MOCKED] Message investigation with one URL performs extraction and inspection", async () => {
    // Mock TinyFish execution
    vi.spyOn(tinyfishModule, "executeTinyFishInvestigation").mockResolvedValueOnce({
      success: true,
      goalFailed: false,
      eventsCount: 3,
      rawAgentText: "Loaded legitimate application portal with verified SSL certificate.",
      observedFacts: {
        pageTitle: "Official Career Portal",
        visiblePurpose: "Corporate recruitment and candidate onboarding",
      },
    });

    const payload = {
      input: "Please check our careers page: https://careers.example-corp.com/jobs/dev-101",
      messageText: "Please check our careers page: https://careers.example-corp.com/jobs/dev-101",
      analysisMode: "message",
    };

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.report).toBeDefined();
    expect(data.report.originalUrl).toBe("https://careers.example-corp.com/jobs/dev-101");
  });

  it("[MOCKED] Message investigation with multiple URLs returns disambiguation response", async () => {
    const payload = {
      input: "Compare our two candidate links: https://example.com/apply1 and https://example.com/apply2",
      messageText: "Compare our two candidate links: https://example.com/apply1 and https://example.com/apply2",
      analysisMode: "message",
    };

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.multipleUrls).toBe(true);
    expect(data.extractedUrls).toHaveLength(2);
    expect(data.extractedUrls).toContain("https://example.com/apply1");
    expect(data.extractedUrls).toContain("https://example.com/apply2");
  });

  it("[MOCKED] Sensitive credentials in messages are redacted before audit recording", async () => {
    const sensitiveMessage = "Your OTP is 987654 and your secret token is sk_live_secretkey998877. Claim your reward at https://rewards.example.com";

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: sensitiveMessage,
        messageText: sensitiveMessage,
        analysisMode: "message",
      }),
    });

    // Mock TinyFish
    vi.spyOn(tinyfishModule, "executeTinyFishInvestigation").mockResolvedValueOnce({
      success: true,
      eventsCount: 1,
      rawAgentText: "Loaded reward verification portal",
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    // Raw credentials must NEVER be reflected
    const rawOutput = JSON.stringify(data);
    expect(rawOutput).not.toContain("sk_live_secretkey998877");
    expect(rawOutput).not.toContain("987654");
  });

  // =========================================================================
  // 3. ERROR HANDLING & NEVER FALSE LOW RISK
  // =========================================================================

  it("[MOCKED] Upstream crawler HTTP 403 anti-bot error halts safely as Unknown (NEVER false Low Risk)", async () => {
    vi.spyOn(tinyfishModule, "executeTinyFishInvestigation").mockRejectedValueOnce(
      new Error("HTTP 403 Forbidden: Target perimeter firewall rejected sandbox crawler.")
    );

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ input: "https://suspicious-target-with-firewall.com" }),
    });

    const res = await POST(req);
    expect(res.status).toBe(502);
    const data = await res.json();
    expect(data.error).toBeDefined();
    expect(data.report).toBeDefined();

    // CRITICAL: A failed crawler probe must NEVER be represented as Low observed risk
    expect(data.report.riskOutcome).toBe("Unknown");
    expect(data.report.outcomeReason).toContain("HTTP 403 Forbidden");
  });

  it("[MOCKED] Investigation timeout halts safely as Unknown with HTTP 504", async () => {
    vi.spyOn(tinyfishModule, "executeTinyFishInvestigation").mockRejectedValueOnce(
      new Error("Investigation timed out after 110s.")
    );

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ input: "https://extremely-slow-domain.com" }),
    });

    const res = await POST(req);
    expect(res.status).toBe(504);
    const data = await res.json();
    expect(data.error).toContain("timed out");
    expect(data.report.riskOutcome).toBe("Unknown");
  });

  it("[MOCKED] Database persistence failure does not crash investigation; falls back to ephemeral storage", async () => {
    vi.spyOn(dbModule, "saveInvestigation").mockRejectedValueOnce(
      new Error("Neon connection pool exhausted")
    );

    const req = new Request(`${CANONICAL_ORIGIN}/api/investigate`, {
      method: "POST",
      headers: {
        Origin: CANONICAL_ORIGIN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: "Job offer from Microsoft: congratulations you are shortlisted.",
        analysisMode: "message",
      }),
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.report.persisted).toBe(false);
    expect(data.report.storageMode).toBe("ephemeral");
  });
});
