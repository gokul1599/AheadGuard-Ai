import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OPTIONS, POST } from "../app/api/investigate/route";

describe("API Security, Secret Redaction & Hardened CORS", () => {
  const SECRET_KEY = "tf_live_secret_key_998877665544332211";
  const APPROVED_EXTENSION_ID = "abcdefghijklmnopqrstuvwxyzabcdef";
  const originalEnv = process.env.TINYFISH_API_KEY;
  const originalAllowedExtensions = process.env.ALLOWED_EXTENSION_IDS;
  const originalFetch = global.fetch;

  beforeEach(() => {
    process.env.TINYFISH_API_KEY = SECRET_KEY;
    process.env.ALLOWED_EXTENSION_IDS = APPROVED_EXTENSION_ID;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env.TINYFISH_API_KEY = originalEnv;
    process.env.ALLOWED_EXTENSION_IDS = originalAllowedExtensions;
    global.fetch = originalFetch;
  });

  it("Test 20: Client-facing errors never reveal API secrets or internal stack traces", async () => {
    // Simulate an upstream network failure where the secret might be used in the internal request
    global.fetch = vi.fn().mockImplementation((_url, init) => {
      // Simulate an internal exception inside fetch
      const headers = init?.headers as Record<string, string>;
      const authHeader = headers?.["X-API-Key"];
      throw new Error(`Connection to TinyFish failed with internal key ${authHeader} at /var/internal/token.js:45`);
    });

    const request = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: "https://example.com" }),
    });

    const response = await POST(request);
    const bodyText = await response.text();

    // Verify response status
    expect([500, 502, 504]).toContain(response.status);

    // CRITICAL: The secret API key must NEVER be leaked in the client response
    expect(bodyText).not.toContain(SECRET_KEY);
    // Stack trace paths like /var/internal or line numbers should not be leaked to the client
    expect(bodyText).not.toContain("token.js:45");
  });

  it("Test 20b: Missing API key response provides actionable instructions without leaking environment variables", async () => {
    delete process.env.TINYFISH_API_KEY;

    const request = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: "https://example.com" }),
    });

    const response = await POST(request);
    expect(response.status).toBe(503);

    const body = await response.json();
    expect(body.error).toMatch(/TinyFish is not configured yet/i);
    // Verify no process.env dump
    expect(JSON.stringify(body)).not.toContain("PATH");
    expect(JSON.stringify(body)).not.toContain("NODE_ENV");
  });

  // Section 2: Hardened CORS Allowlist Verification
  it("CORS 1: Approved extension origin configured in ALLOWED_EXTENSION_IDS receives permissive CORS headers", async () => {
    const origin = `chrome-extension://${APPROVED_EXTENSION_ID}`;
    const req = new Request("http://localhost:3000/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: origin },
    });

    const res = await OPTIONS(req);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
  });

  it("CORS 2: Syntactically valid 32-character extension ID NOT in allowlist is rejected with 403 Forbidden", async () => {
    const unapprovedOrigin = "chrome-extension://zyxwvutsrqponmlkjihgfedcbazyxwvu";
    const req = new Request("http://localhost:3000/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: unapprovedOrigin },
    });

    const res = await OPTIONS(req);
    expect(res.status).toBe(403);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();

    // Verify POST is also rejected
    const postReq = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: {
        Origin: unapprovedOrigin,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ input: "https://example.com" }),
    });
    const postRes = await POST(postReq);
    expect(postRes.status).toBe(403);
  });

  it("CORS 3: Malformed extension origin is rejected immediately", async () => {
    const malformed = [
      "chrome-extension://short",
      "chrome-extension://INVALID_UPPERCASE_CHARACTERS12",
      "chrome-extension://contains-invalid-characters!!",
      "chrome-extension://32charactersnumber123456789012",
    ];

    for (const origin of malformed) {
      const req = new Request("http://localhost:3000/api/investigate", {
        method: "OPTIONS",
        headers: { Origin: origin },
      });
      const res = await OPTIONS(req);
      expect(res.status).toBe(403);
    }
  });

  it("CORS 4: Unauthorized website origins receive 403 Forbidden", async () => {
    const webOrigins = [
      "https://attacker.com",
      "https://phishing-site.online",
      "http://untrusted.org:8080",
    ];

    for (const origin of webOrigins) {
      const req = new Request("http://localhost:3000/api/investigate", {
        method: "OPTIONS",
        headers: { Origin: origin },
      });
      const res = await OPTIONS(req);
      expect(res.status).toBe(403);
    }
  });

  it("CORS 5: Required local development origins (localhost, 127.0.0.1) are permitted", async () => {
    const devOrigins = [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://127.0.0.1:3000",
    ];

    for (const origin of devOrigins) {
      const req = new Request("http://localhost:3000/api/investigate", {
        method: "OPTIONS",
        headers: { Origin: origin },
      });
      const res = await OPTIONS(req);
      expect(res.status).toBe(204);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    }
  });

  it("CORS 6: Missing or empty ALLOWED_EXTENSION_IDS fails safely (rejects all extensions)", async () => {
    delete process.env.ALLOWED_EXTENSION_IDS;
    delete process.env.AHEADGUARD_EXTENSION_ID;

    const req = new Request("http://localhost:3000/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: `chrome-extension://${APPROVED_EXTENSION_ID}` },
    });

    const res = await OPTIONS(req);
    expect(res.status).toBe(403);
  });

  // Section 3: Request Payload Hardening
  it("Payload Hardening: Oversized request payload (> 16KB) is rejected with 413 Payload Too Large", async () => {
    const request = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": "20000",
      },
      body: JSON.stringify({ input: "https://example.com" }),
    });

    const response = await POST(request);
    expect(response.status).toBe(413);
    const body = await response.json();
    expect(body.error).toMatch(/too large/i);
  });

  it("Payload Hardening: Malformed JSON body returns clean 400 Bad Request error without stack traces", async () => {
    const request = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-valid-json{",
    });

    const response = await POST(request);
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toMatch(/invalid json/i);
    expect(JSON.stringify(body)).not.toContain("SyntaxError");
  });
});
