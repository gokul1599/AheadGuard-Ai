import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OPTIONS, POST, GET } from "../app/api/investigate/route";
import { resetRateLimitForTesting } from "../lib/api-security";

describe("API Security, Secret Redaction & Hardened CORS", () => {
  const SECRET_KEY = "tf_live_secret_key_998877665544332211";
  const APPROVED_EXTENSION_ID = "abcdefghijklmnopqrstuvwxyzabcdef";
  const originalEnv = process.env.TINYFISH_API_KEY;
  const originalAllowedExtensions = process.env.ALLOWED_EXTENSION_IDS;
  const originalFetch = global.fetch;

  beforeEach(() => {
    process.env.TINYFISH_API_KEY = SECRET_KEY;
    process.env.ALLOWED_EXTENSION_IDS = APPROVED_EXTENSION_ID;
    resetRateLimitForTesting();
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
  it("CORS 0: Exact production dashboard origin (https://aheadguard-ai.vercel.app) is permitted for OPTIONS preflight and POST", async () => {
    const prodOrigin = "https://aheadguard-ai.vercel.app";

    // 1. Verify OPTIONS preflight receives permissive CORS headers
    const optionsReq = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
      method: "OPTIONS",
      headers: { Origin: prodOrigin },
    });
    const optionsRes = await OPTIONS(optionsReq);
    expect(optionsRes.status).toBe(204);
    expect(optionsRes.headers.get("Access-Control-Allow-Origin")).toBe(prodOrigin);
    expect(optionsRes.headers.get("Access-Control-Allow-Methods")).toContain("POST");

    // 2. Verify POST request from production dashboard is permitted
    global.fetch = vi.fn().mockImplementation((_url, init) => {
      const isSse = init?.headers?.["Accept"]?.includes("text/event-stream");
      if (isSse) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ "content-type": "text/event-stream" }),
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(
                new TextEncoder().encode(
                  'event: report\ndata: {"riskOutcome":"Low observed risk","originalUrl":"https://example.com"}\n\n'
                )
              );
              controller.close();
            },
          }),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          status: "completed",
          report: { riskOutcome: "Low observed risk", originalUrl: "https://example.com" },
        }),
      });
    });

    const postReq = new Request("https://aheadguard-ai.vercel.app/api/investigate", {
      method: "POST",
      headers: {
        Origin: prodOrigin,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ input: "https://example.com" }),
    });
    const postRes = await POST(postReq);
    expect(postRes.status).toBe(200);
    expect(postRes.headers.get("Access-Control-Allow-Origin")).toBe(prodOrigin);
  });

  it("CORS 0b: OPTIONS preflight with missing Origin header returns 403 Forbidden", async () => {
    const req = new Request("http://localhost:3000/api/investigate", {
      method: "OPTIONS",
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(403);
  });

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
      "https://evil.vercel.app",
      "https://unapproved.vercel.app",
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

  // Section 4: Public API Abuse Protection & Rate Limiting
  it("Rate Limiting: Sliding-window rate limiter rejects excessive requests from same IP with 429", async () => {
    const { checkRateLimit, resetRateLimitForTesting } = await import("../lib/api-security");
    resetRateLimitForTesting();

    const testIp = "198.51.100.42";

    // 1. First 4 requests within burst limit are allowed
    for (let i = 0; i < 4; i++) {
      const res = checkRateLimit(testIp);
      expect(res.allowed).toBe(true);
      expect(res.limit).toBe(20);
    }

    // 5th request hits the burst limit (max 5 in 5 seconds)
    const fifth = checkRateLimit(testIp);
    expect(fifth.allowed).toBe(true);

    // 6th request trips the burst rate limit
    const tripped = checkRateLimit(testIp);
    expect(tripped.allowed).toBe(false);
    expect(tripped.retryAfter).toBeGreaterThanOrEqual(1);

    // 2. Integration test via POST handler: verify HTTP 429 and Retry-After header
    const postReq = new Request("http://localhost:3000/api/investigate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-real-ip": testIp,
      },
      body: JSON.stringify({ input: "https://example.com" }),
    });

    const postRes = await POST(postReq);
    expect(postRes.status).toBe(429);
    expect(postRes.headers.get("Retry-After")).toBeDefined();
    expect(postRes.headers.get("X-RateLimit-Limit")).toBe("20");

    const errBody = await postRes.json();
    expect(errBody.error).toMatch(/too many investigation requests/i);

    resetRateLimitForTesting();
  });

  // Section 5: GET Endpoint Security & Database Health / History Protection
  it("GET Handler: Enforces CORS origin check and rejects unauthorized origins with 403", async () => {
    const getReq = new Request("http://localhost:3000/api/investigate", {
      method: "GET",
      headers: { Origin: "https://malicious-attacker.com" },
    });
    const res = await GET(getReq);
    expect(res.status).toBe(403);
  });

  it("GET Handler: Anonymous access to individual record by ID is rejected with 401 Unauthorized", async () => {
    const getReq = new Request("http://localhost:3000/api/investigate?id=inv_sample_12345", {
      method: "GET",
    });
    const res = await GET(getReq);
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error).toMatch(/unauthorized.*administrator credentials required/i);
  });

  it("GET Handler: Access to individual record with invalid admin token is rejected with 401 Unauthorized", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      process.env.AHEADGUARD_ADMIN_KEY = "test_admin_secret_token_12345";
      const getReq = new Request("http://localhost:3000/api/investigate?id=inv_sample_12345", {
        method: "GET",
        headers: { Authorization: "Bearer wrong_token_value" },
      });
      const res = await GET(getReq);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.error).toMatch(/unauthorized.*administrator credentials required/i);
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Unauthenticated history request is rejected with 401 Unauthorized", async () => {
    const getReq = new Request("http://localhost:3000/api/investigate?action=history", {
      method: "GET",
    });
    const res = await GET(getReq);
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error).toMatch(/unauthorized/i);
  });

  it("GET Handler: History request when AHEADGUARD_ADMIN_KEY is unconfigured or whitespace-only is rejected with 401 Unauthorized", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      // 1. Unconfigured
      delete process.env.AHEADGUARD_ADMIN_KEY;
      const getReq1 = new Request("http://localhost:3000/api/investigate?action=history", {
        method: "GET",
        headers: { Authorization: "Bearer any_token" },
      });
      const res1 = await GET(getReq1);
      expect(res1.status).toBe(401);
      const body1 = await res1.json();
      expect(body1.error).toMatch(/unauthorized.*administrator credentials required/i);

      // 2. Empty string
      process.env.AHEADGUARD_ADMIN_KEY = "";
      const res2 = await GET(getReq1);
      expect(res2.status).toBe(401);

      // 3. Whitespace only
      process.env.AHEADGUARD_ADMIN_KEY = "   \t \n  ";
      const res3 = await GET(getReq1);
      expect(res3.status).toBe(401);
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Proves no accidental alias fallback exists (ADMIN_API_KEY does not authorize requests)", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    const originalAlias = (process.env as Record<string, string | undefined>).ADMIN_API_KEY;
    try {
      delete process.env.AHEADGUARD_ADMIN_KEY;
      (process.env as Record<string, string | undefined>).ADMIN_API_KEY = "legacy_or_alias_token_value_32bytes";

      const getReq = new Request("http://localhost:3000/api/investigate?action=history", {
        method: "GET",
        headers: { Authorization: "Bearer legacy_or_alias_token_value_32bytes" },
      });
      const res = await GET(getReq);
      expect(res.status).toBe(401);

      const body = await res.json();
      expect(body.error).toMatch(/unauthorized.*administrator credentials required/i);
      expect(JSON.stringify(body)).not.toContain("legacy_or_alias_token_value_32bytes");
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
      if (originalAlias !== undefined) {
        (process.env as Record<string, string | undefined>).ADMIN_API_KEY = originalAlias;
      } else {
        delete (process.env as Record<string, string | undefined>).ADMIN_API_KEY;
      }
    }
  });

  it("GET Handler: History and record requests with malformed, non-Bearer, or oversized tokens reject with 401 without secret leakage", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      process.env.AHEADGUARD_ADMIN_KEY = "valid_configured_admin_key_32bytes";

      const malformedHeaders = [
        "Basic dXNlcjpwYXNz",
        "Token valid_configured_admin_key_32bytes",
        "Digest valid_configured_admin_key_32bytes",
        "Bearer",
        "Bearer ",
        "Bearer    ",
        "Bearer\tvalid_configured_admin_key_32bytes", // tab separator strictly rejected per RFC 6750 grammar (requires 1*SP)
        "Bearer: valid_configured_admin_key_32bytes",
        "Bearer VALID_CONFIGURED_ADMIN_KEY_32BYTES", // case-sensitive token mismatch
        "Bearer valid_configured admin_key_32bytes", // internal space mismatch
        "Bearer valid_configured;DROP", // disallowed characters
        "Bearer valid_configured=admin", // invalid padding placement
        "Bearer =valid_configured", // padding at start
        "Bearer wrong_value_here",
        `Bearer ${"x".repeat(1000)}`,
      ];

      for (const authHeader of malformedHeaders) {
        resetRateLimitForTesting();
        // Test against ?action=history
        const historyReq = new Request("http://localhost:3000/api/investigate?action=history", {
          method: "GET",
          headers: { Authorization: authHeader },
        });
        const historyRes = await GET(historyReq);
        expect(historyRes.status).toBe(401);
        const historyBody = await historyRes.json();
        expect(historyBody.error).toBe("Unauthorized: administrator credentials required to access stored records.");
        expect(JSON.stringify(historyBody)).not.toContain("valid_configured_admin_key_32bytes");

        resetRateLimitForTesting();
        // Test against ?id=inv_sample_12345
        const idReq = new Request("http://localhost:3000/api/investigate?id=inv_sample_12345", {
          method: "GET",
          headers: { Authorization: authHeader },
        });
        const idRes = await GET(idReq);
        expect(idRes.status).toBe(401);
        const idBody = await idRes.json();
        expect(idBody.error).toBe("Unauthorized: administrator credentials required to access stored records.");
        expect(JSON.stringify(idBody)).not.toContain("valid_configured_admin_key_32bytes");
      }
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Authorized history and report requests succeed with case-insensitive Bearer scheme variants", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      process.env.AHEADGUARD_ADMIN_KEY = "test_admin_secret_token_12345";

      const validSchemeHeaders = [
        "Bearer test_admin_secret_token_12345",
        "bearer test_admin_secret_token_12345",
        "BEARER test_admin_secret_token_12345",
        "bEaReR test_admin_secret_token_12345",
        "Bearer   test_admin_secret_token_12345", // multiple whitespace separator allowed by RFC 7235
      ];

      for (const authHeader of validSchemeHeaders) {
        resetRateLimitForTesting();
        const getReq = new Request("http://localhost:3000/api/investigate?action=history", {
          method: "GET",
          headers: { Authorization: authHeader },
        });
        const res = await GET(getReq);
        expect(res.status).toBe(200);

        const body = await res.json();
        expect(Array.isArray(body.investigations)).toBe(true);
      }
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Authorized history request with matching admin bearer token succeeds", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      process.env.AHEADGUARD_ADMIN_KEY = "test_admin_secret_token_12345";
      const getReq = new Request("http://localhost:3000/api/investigate?action=history", {
        method: "GET",
        headers: { Authorization: "Bearer test_admin_secret_token_12345" },
      });
      const res = await GET(getReq);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(Array.isArray(body.investigations)).toBe(true);
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Authorized individual record request validates ID format and returns 400 for malformed ID", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      process.env.AHEADGUARD_ADMIN_KEY = "test_admin_secret_token_12345";
      const getReq = new Request("http://localhost:3000/api/investigate?id=inv_invalid;--DROP", {
        method: "GET",
        headers: { Authorization: "Bearer test_admin_secret_token_12345" },
      });
      const res = await GET(getReq);
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body.error).toMatch(/invalid investigation id/i);
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Authorized request for non-existent record returns 404 Not Found", async () => {
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;
    try {
      process.env.AHEADGUARD_ADMIN_KEY = "test_admin_secret_token_12345";
      const getReq = new Request("http://localhost:3000/api/investigate?id=inv_nonexistent_99999", {
        method: "GET",
        headers: { Authorization: "Bearer test_admin_secret_token_12345" },
      });
      const res = await GET(getReq);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body.error).toMatch(/investigation report not found/i);
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("GET Handler: Returns safe database health status without disclosing internal credentials or schema", async () => {
    const getReq = new Request("http://localhost:3000/api/investigate", {
      method: "GET",
    });
    const res = await GET(getReq);
    expect([200, 503]).toContain(res.status);

    const body = await res.json();
    expect(body.db).toBeDefined();
    // Verify no secret, password, or host leakage
    const jsonStr = JSON.stringify(body);
    expect(jsonStr).not.toContain("password");
    expect(jsonStr).not.toContain("neon.tech");
    expect(jsonStr).not.toContain("PostgreSQL 18");
  });

  it("verifyAdminAuth: Exhaustively handles missing, invalid, wrong-length, same-length mismatch, and malformed tokens", async () => {
    const { verifyAdminAuth } = await import("../lib/api-security");
    const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;

    try {
      // 1. Unconfigured admin key fails closed
      delete process.env.AHEADGUARD_ADMIN_KEY;
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer test" } }))).toBe(false);

      // 2. Empty string and whitespace-only admin key fail closed
      process.env.AHEADGUARD_ADMIN_KEY = "";
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer test" } }))).toBe(false);

      process.env.AHEADGUARD_ADMIN_KEY = "   \t \n  ";
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer test" } }))).toBe(false);

      // 3. Unintended alias ADMIN_API_KEY in environment fails closed when AHEADGUARD_ADMIN_KEY is unset
      delete process.env.AHEADGUARD_ADMIN_KEY;
      (process.env as Record<string, string | undefined>).ADMIN_API_KEY = "alias_admin_key_32bytes_value";
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer alias_admin_key_32bytes_value" } }))).toBe(false);
      delete (process.env as Record<string, string | undefined>).ADMIN_API_KEY;

      // Set valid canonical admin key (32 chars)
      process.env.AHEADGUARD_ADMIN_KEY = "0123456789abcdef0123456789abcdef";

      // 4. Missing authorization header
      expect(verifyAdminAuth(new Request("http://localhost"))).toBe(false);

      // 5. Non-Bearer schemes (Basic, Token, Digest, etc.)
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Basic dXNlcjpwYXNz" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Token 0123456789abcdef0123456789abcdef" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Digest 0123456789abcdef0123456789abcdef" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer" } }))).toBe(false);

      // 6. Case-insensitive Bearer scheme variants succeed (RFC 7235 / RFC 9110 Section 11.1)
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 0123456789abcdef0123456789abcdef" } }))).toBe(true);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "bearer 0123456789abcdef0123456789abcdef" } }))).toBe(true);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "BEARER 0123456789abcdef0123456789abcdef" } }))).toBe(true);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "bEaReR 0123456789abcdef0123456789abcdef" } }))).toBe(true);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer   0123456789abcdef0123456789abcdef" } }))).toBe(true);

      // 7. Tab separator strictly rejected per RFC 6750 Section 2.1 (requires 1*SP, ASCII space 0x20)
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer\t0123456789abcdef0123456789abcdef" } }))).toBe(false);

      // 8. Token whitespace preservation: trailing whitespace in raw header must NOT be trimmed into validity
      const reqTrailingSpace = {
        headers: {
          get: (name: string) => (name.toLowerCase() === "authorization" ? "Bearer 0123456789abcdef0123456789abcdef " : null),
        },
      } as unknown as Request;
      expect(verifyAdminAuth(reqTrailingSpace)).toBe(false);

      // Raw unnormalized header edge cases (tested via direct Request mock to bypass Fetch API auto-trimming)
      const createMockReq = (headerVal: string) => ({
        headers: {
          get: (name: string) => (name.toLowerCase() === "authorization" ? headerVal : null),
        },
      } as unknown as Request);

      // Leading spaces before scheme strictly rejected
      expect(verifyAdminAuth(createMockReq(" Bearer 0123456789abcdef0123456789abcdef"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("   bearer 0123456789abcdef0123456789abcdef"))).toBe(false);

      // Trailing newlines / carriage returns / control characters strictly rejected
      expect(verifyAdminAuth(createMockReq("Bearer 0123456789abcdef0123456789abcdef\n"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("Bearer 0123456789abcdef0123456789abcdef\r"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("Bearer 0123456789abcdef0123456789abcdef\r\n"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("Bearer 0123456789abcdef0123456789abcdef\0"))).toBe(false);

      // 9. Token case-sensitivity: token value differs by casing
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 0123456789ABCDEF0123456789ABCDEF" } }))).toBe(false);

      // 10. RFC 6750 b64token grammar validation: reject embedded spaces, tabs, disallowed characters, and invalid padding
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 012345 6789abcdef" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 012345\t6789abcdef" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 012345;DROP" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 012345$key" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 012345=admin" } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer =012345" } }))).toBe(false);

      // 11. Empty Bearer token
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer " } }))).toBe(false);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer    " } }))).toBe(false);

      // 12. Wrong-length token (too short)
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 012345" } }))).toBe(false);

      // 13. Wrong-length token (too long)
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 0123456789abcdef0123456789abcdefextra" } }))).toBe(false);

      // 14. Same-length token with 1 character difference
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: "Bearer 0123456789abcdef0123456789abcdeg" } }))).toBe(false);

      // 15. Oversized token (> 512 characters) rejected early to prevent resource exhaustion
      const hugeToken = "a".repeat(1000);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: `Bearer ${hugeToken}` } }))).toBe(false);

      // 16. Oversized Authorization header (> 1024 characters) rejected early
      const hugeHeader = "Bearer " + "b".repeat(2000);
      expect(verifyAdminAuth(new Request("http://localhost", { headers: { Authorization: hugeHeader } }))).toBe(false);
    } finally {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    }
  });

  it("getClientIp: Rigorously verifies trusted proxy IP extraction, spoofing protection, IPv6, and elimination of unverified fallback", async () => {
    const { getClientIp, normalizeIp } = await import("../lib/api-security");

    // 1. Valid canonical client IP (x-real-ip)
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "198.51.100.10" } }))).toBe("198.51.100.10");

    // 2. Missing canonical IP falls back safely to loopback
    expect(getClientIp(new Request("http://localhost"))).toBe("127.0.0.1");

    // 3. Empty canonical IP falls back safely to loopback
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "" } }))).toBe("127.0.0.1");

    // 4. Malformed canonical IP falls back safely to loopback
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "malicious-string" } }))).toBe("127.0.0.1");

    // 5. Attacker-supplied x-forwarded-for when canonical IP is missing: NEVER trusted, falls back to loopback
    expect(getClientIp(new Request("http://localhost", { headers: { "x-forwarded-for": "203.0.113.50" } }))).toBe("127.0.0.1");

    // 6. Attacker-supplied x-forwarded-for when canonical IP is invalid: NEVER trusted, falls back to loopback
    expect(
      getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "malicious-string", "x-forwarded-for": "198.51.100.99" } }))
    ).toBe("127.0.0.1");

    // 7. Conflicting canonical and forwarding headers: canonical x-real-ip strictly overrides attacker x-forwarded-for
    const spoofAttempt = new Request("http://localhost", {
      headers: {
        "x-real-ip": "198.51.100.10",
        "x-forwarded-for": "1.2.3.4, 5.6.7.8",
      },
    });
    expect(getClientIp(spoofAttempt)).toBe("198.51.100.10");

    // 8. Multiple comma-separated forwarding addresses: unverified, falls back to loopback
    expect(
      getClientIp(new Request("http://localhost", { headers: { "x-forwarded-for": "198.51.100.1, 10.0.0.1, 172.16.0.1" } }))
    ).toBe("127.0.0.1");

    // 9. Empty and whitespace-only forwarding entries
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "   ", "x-forwarded-for": "  ,  , " } }))).toBe("127.0.0.1");

    // 10. Malformed IPv4 values (e.g. out-of-range octets, extra segments)
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "999.999.999.999" } }))).toBe("127.0.0.1");
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "1.2.3.4.5" } }))).toBe("127.0.0.1");

    // 11. Malformed IPv6 values
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "2001:xyz::1" } }))).toBe("127.0.0.1");
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "2001:db8:::1" } }))).toBe("127.0.0.1");

    // 12. Valid IPv6 support
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "2001:db8::1" } }))).toBe("2001:db8::1");
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "2001:db8:85a3::8a2e:370:7334" } }))).toBe(
      "2001:db8:85a3::8a2e:370:7334"
    );

    // 13. IPv4-mapped IPv6 normalization
    expect(normalizeIp("::ffff:198.51.100.1")).toBe("198.51.100.1");
    expect(normalizeIp("  ::ffff:203.0.113.195  ")).toBe("203.0.113.195");
    expect(normalizeIp("2001:db8::1")).toBe("2001:db8::1");
    expect(normalizeIp("198.51.100.10")).toBe("198.51.100.10");
    expect(getClientIp(new Request("http://localhost", { headers: { "x-real-ip": "::ffff:198.51.100.42" } }))).toBe("198.51.100.42");
  });

  it("hasTrustedClientIp: Accurately differentiates authoritative canonical IP from unverified fallback", async () => {
    const { hasTrustedClientIp } = await import("../lib/api-security");

    // Authoritative valid IPv4 and IPv6
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "198.51.100.42" } }))).toBe(true);
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "2001:db8::1" } }))).toBe(true);
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "::ffff:198.51.100.42" } }))).toBe(true);

    // Missing, empty, or whitespace-only x-real-ip
    expect(hasTrustedClientIp(new Request("http://localhost"))).toBe(false);
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "" } }))).toBe(false);
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "   " } }))).toBe(false);

    // Malformed IP
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "not-an-ip" } }))).toBe(false);
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-real-ip": "999.999.999.999" } }))).toBe(false);

    // Forwarding headers do not make it trusted
    expect(hasTrustedClientIp(new Request("http://localhost", { headers: { "x-forwarded-for": "198.51.100.42" } }))).toBe(false);
  });

  it("checkRateLimit: Rigorously verifies quota exhaustion, retry-after calculation, IP isolation, and anti-rotation evasion", async () => {
    const { checkRateLimit, resetRateLimitForTesting, getClientIp } = await import("../lib/api-security");
    resetRateLimitForTesting();

    const ipA = "198.51.100.55";
    const ipB = "198.51.100.66";

    // 1. Initial requests for ipA succeed with decrementing remaining quota
    const res1 = checkRateLimit(ipA);
    expect(res1.allowed).toBe(true);
    expect(res1.limit).toBe(20);
    expect(res1.remaining).toBe(19);

    // 2. Burst limit test: 5 requests in 5 seconds
    checkRateLimit(ipA);
    checkRateLimit(ipA);
    checkRateLimit(ipA);
    const res5 = checkRateLimit(ipA);
    expect(res5.allowed).toBe(true);
    expect(res5.remaining).toBe(15);

    // 6th immediate request hits burst limit
    const res6 = checkRateLimit(ipA);
    expect(res6.allowed).toBe(false);
    expect(res6.remaining).toBe(0);
    expect(res6.retryAfter).toBeGreaterThanOrEqual(1);

    // 3. Different effective IP (ipB) is completely unaffected by ipA's exhaustion
    const resB = checkRateLimit(ipB);
    expect(resB.allowed).toBe(true);
    expect(resB.remaining).toBe(19);

    // 4. Anti-rotation evasion: Attacker rotating x-forwarded-for without x-real-ip
    resetRateLimitForTesting();
    for (let i = 1; i <= 5; i++) {
      const forgedReq = new Request("http://localhost", {
        headers: { "x-forwarded-for": `10.0.0.${i}` },
      });
      const resolvedIp = getClientIp(forgedReq);
      expect(resolvedIp).toBe("127.0.0.1"); // All map to fallback bucket
      const rateRes = checkRateLimit(resolvedIp);
      expect(rateRes.allowed).toBe(true);
    }

    // 6th request with yet another forged x-forwarded-for header is blocked by the shared fallback bucket
    const sixthForgedReq = new Request("http://localhost", {
      headers: { "x-forwarded-for": "10.0.0.6" },
    });
    const sixthResolvedIp = getClientIp(sixthForgedReq);
    expect(sixthResolvedIp).toBe("127.0.0.1");
    const blockedRes = checkRateLimit(sixthResolvedIp);
    expect(blockedRes.allowed).toBe(false);
    expect(blockedRes.retryAfter).toBeGreaterThanOrEqual(1);

    // 5. Shared fallback bucket availability abuse & legitimate client isolation:
    // Any subsequent unverified request lacking x-real-ip is also blocked due to shared fallback exhaustion
    const unverifiedReq = new Request("http://localhost");
    const unverifiedIp = getClientIp(unverifiedReq);
    expect(unverifiedIp).toBe("127.0.0.1");
    const unverifiedRes = checkRateLimit(unverifiedIp);
    expect(unverifiedRes.allowed).toBe(false);
    expect(unverifiedRes.retryAfter).toBeGreaterThanOrEqual(1);

    // CRITICAL ISOLATION: A legitimate client with a valid canonical x-real-ip is completely unaffected
    const legitimateClientReq = new Request("http://localhost", {
      headers: { "x-real-ip": "198.51.100.99" },
    });
    const legitimateIp = getClientIp(legitimateClientReq);
    expect(legitimateIp).toBe("198.51.100.99");
    const legitimateRes = checkRateLimit(legitimateIp);
    expect(legitimateRes.allowed).toBe(true);
    expect(legitimateRes.remaining).toBe(19);

    resetRateLimitForTesting();
  });

  // Section 6: Multiple-URL Response Privacy & Route Behavior (Phase II Security Gate)
  describe("Section 6: Multiple-URL Response Privacy & Dispatch Safety", () => {
    const SECRET_MARKER = "TEST_SECRET_DO_NOT_LEAK";

    it("Multiple-URL JSON Mode: Excludes secret-bearing URLs and never leaks raw secret tokens in payload", async () => {
      const mixedMessage = `Please review these listings: https://safe.example.test/jobs?page=2 and https://safe.example.test/continue?access_token=${SECRET_MARKER}`;

      const req = new Request("http://localhost:3000/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: mixedMessage }),
      });

      const res = await POST(req);
      expect(res.status).toBe(200);

      const rawText = await res.text();
      // CRITICAL: The secret token must NEVER appear anywhere in the response text
      expect(rawText).not.toContain(SECRET_MARKER);

      const data = JSON.parse(rawText);
      expect(data.multipleUrls).toBe(true);
      expect(data.extractedUrls).toContain("https://safe.example.test/jobs?page=2");
      // The secret-bearing URL must not be present in extractedUrls
      expect(data.extractedUrls).not.toContain(`https://safe.example.test/continue?access_token=${SECRET_MARKER}`);
    });

    it("Multiple-URL SSE Mode: Emits multiple_urls event with scrubbed URLs and zero secret leakage", async () => {
      const mixedMessage = `Please review these listings: https://safe.example.test/jobs?page=2 and https://safe.example.test/continue?access_token=${SECRET_MARKER}`;

      const req = new Request("http://localhost:3000/api/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify({ input: mixedMessage }),
      });

      const res = await POST(req);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");

      const streamText = await res.text();
      // CRITICAL: Stream output must NEVER contain the secret token
      expect(streamText).not.toContain(SECRET_MARKER);
      expect(streamText).toContain("event: multiple_urls");
      expect(streamText).toContain("https://safe.example.test/jobs?page=2");
    });

    it("Multiple-URL Variants: Strips api_key, client_secret, refresh_token, password, mixed-case, and hash fragments", async () => {
      const variants = [
        `Check https://safe.example.test/careers?sort=asc and https://unsafe.example.test/auth?api_key=${SECRET_MARKER}`,
        `Check https://safe.example.test/careers?sort=asc and https://unsafe.example.test/auth?client_secret=${SECRET_MARKER}`,
        `Check https://safe.example.test/careers?sort=asc and https://unsafe.example.test/auth?refresh_token=${SECRET_MARKER}`,
        `Check https://safe.example.test/careers?sort=asc and https://unsafe.example.test/auth?password=${SECRET_MARKER}`,
        `Check https://safe.example.test/careers?sort=asc and https://unsafe.example.test/auth?Access_Token=${SECRET_MARKER}`,
        `Check https://safe.example.test/careers?sort=asc and https://unsafe.example.test/auth#access_token=${SECRET_MARKER}`,
      ];

      for (const msg of variants) {
        resetRateLimitForTesting();
        const req = new Request("http://localhost:3000/api/investigate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: msg }),
        });

        const res = await POST(req);
        const text = await res.text();
        expect(text).not.toContain(SECRET_MARKER);
        expect(text).toContain("https://safe.example.test/careers?sort=asc");
      }
    });

    it("Multiple-URL All Unsafe: Fails closed with 400 when all extracted links contain credentials", async () => {
      resetRateLimitForTesting();
      const allUnsafeMsg = `Verify your account here: https://phish.test/step1?token=${SECRET_MARKER} or here: https://phish.test/step2?password=${SECRET_MARKER}`;

      const req = new Request("http://localhost:3000/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: allUnsafeMsg }),
      });

      const res = await POST(req);
      expect(res.status).toBe(400);

      const errText = await res.text();
      expect(errText).not.toContain(SECRET_MARKER);
      expect(errText).toMatch(/sensitive authentication tokens or credentials/i);
    });

    it("End-to-End Subsequent Selection: Selecting safe URL never dispatches earlier secret-bearing URL to crawler", async () => {
      resetRateLimitForTesting();
      let dispatchedUrlToCrawler = "";

      // Mock TinyFish SSE crawler endpoint
      global.fetch = vi.fn().mockImplementation((_url, init) => {
        const bodyStr = String(init?.body || "");
        if (bodyStr.includes('"url":')) {
          try {
            const parsed = JSON.parse(bodyStr);
            dispatchedUrlToCrawler = parsed.url;
          } catch {
            // ignore
          }
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ "content-type": "text/event-stream" }),
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(
                new TextEncoder().encode(
                  `event: COMPLETE\ndata: ${JSON.stringify({
                    status: "completed",
                    result: {
                      page_title: "Careers Portal",
                      observed_final_url: dispatchedUrlToCrawler,
                      claimed_organization: "Acme Corp",
                      visible_purpose: "Job Listings",
                    },
                  })}\n\n`
                )
              );
              controller.close();
            },
          }),
        });
      });

      // Subsequent request: user picked the safe URL from the multiple-URL modal
      const req = new Request("http://localhost:3000/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input: "https://safe.example.test/jobs?page=2",
          targetUrl: "https://safe.example.test/jobs?page=2",
          messageText: `Please review these listings: https://safe.example.test/jobs?page=2 and https://safe.example.test/continue?access_token=${SECRET_MARKER}`,
        }),
      });

      const res = await POST(req);
      expect(res.status).toBe(200);

      const resText = await res.text();
      // Ensure secret never reflected in report response
      expect(resText).not.toContain(SECRET_MARKER);

      // Verify that TinyFish only received the selected safe URL
      expect(dispatchedUrlToCrawler).toBe("https://safe.example.test/jobs?page=2");
      expect(dispatchedUrlToCrawler).not.toContain(SECRET_MARKER);
    });
  });
});
