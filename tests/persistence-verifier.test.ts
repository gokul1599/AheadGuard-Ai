import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  CANONICAL_PRODUCTION_ORIGIN,
  generatePersistenceMarker,
  buildHarmlessPersistencePayload,
  isLoopbackOrigin,
  validateTargetOrigin,
  sanitizeSecrets,
  parseJsonResponse,
  verifyProductionPersistence,
  runCli,
} from "../scripts/verify-persistence.mjs";

describe("Hardened Production Persistence Verifier", () => {
  const dummyBaseUrl = CANONICAL_PRODUCTION_ORIGIN;
  const dummyAdminKey = "test_super_secret_admin_key_12345678";

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("Marker & Payload Construction", () => {
    it("generates unique persistence markers with correct prefix and entropy", () => {
      const marker1 = generatePersistenceMarker();
      const marker2 = generatePersistenceMarker();

      expect(marker1).toMatch(/^aheadguard-persistence-probe-\d+-[a-f0-9]{16}$/);
      expect(marker2).toMatch(/^aheadguard-persistence-probe-\d+-[a-f0-9]{16}$/);
      expect(marker1).not.toBe(marker2);
    });

    it("builds a harmless text-only payload containing no URLs or external web references", () => {
      const marker = "aheadguard-persistence-probe-12345-abcdef";
      const payload = buildHarmlessPersistencePayload(marker);

      expect(payload.input).toContain(marker);
      expect(payload.input).toContain("AheadGuard automated database persistence verification probe");
      expect(payload.analysisMode).toBe("message");

      // Verify strictly NO URLs exist in the payload
      expect(payload.input).not.toMatch(/https?:\/\//i);
      expect(payload.input).not.toMatch(/www\./i);
      expect(payload.input).not.toMatch(/\.(com|net|org|io|ai|co)/i);
    });
  });

  describe("Target-Origin Authorization & Security Gates", () => {
    it("identifies loopback origins correctly", () => {
      expect(isLoopbackOrigin(new URL("http://localhost:3000"))).toBe(true);
      expect(isLoopbackOrigin(new URL("http://127.0.0.1:8080"))).toBe(true);
      expect(isLoopbackOrigin(new URL("http://[::1]:3000"))).toBe(true);
      expect(isLoopbackOrigin(new URL("https://example.com"))).toBe(false);
      expect(isLoopbackOrigin(new URL("https://aheadguard-ai.vercel.app"))).toBe(false);
    });

    it("accepts canonical production origin in production mode", () => {
      const res = validateTargetOrigin(CANONICAL_PRODUCTION_ORIGIN, true);
      expect(res.valid).toBe(true);
      expect(res.origin).toBe(CANONICAL_PRODUCTION_ORIGIN);
    });

    it("rejects non-canonical origin when --prod is selected", () => {
      const res = validateTargetOrigin("https://evil-spoof.vercel.app", true);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("production mode strictly permits only canonical origin");
      expect(res.error).not.toContain("evil-spoof.vercel.app"); // No raw URL echo
    });

    it("rejects plain HTTP for non-loopback destinations", () => {
      const res = validateTargetOrigin("http://remote-server.com", false, ["http://remote-server.com"]);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("HTTP is only permitted for local loopback development");
      expect(res.error).not.toContain("remote-server.com");
    });

    it("permits plain HTTP for local loopback development", () => {
      const res = validateTargetOrigin("http://localhost:3000", false);
      expect(res.valid).toBe(true);
      expect(res.origin).toBe("http://localhost:3000");

      const resIp = validateTargetOrigin("http://127.0.0.1:3000", false);
      expect(resIp.valid).toBe(true);
      expect(resIp.origin).toBe("http://127.0.0.1:3000");
    });

    it("rejects URL userinfo containing embedded username or password", () => {
      const res = validateTargetOrigin("https://admin:secret@aheadguard-ai.vercel.app", false);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("embedded credentials (userinfo) are rejected");
      expect(res.error).not.toContain("secret");
      expect(res.error).not.toContain("admin");
    });

    it("rejects unsupported schemes like ftp: or javascript:", () => {
      const res = validateTargetOrigin("ftp://example.com", false);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("scheme must be https");
    });

    it("rejects custom targets outside the explicit allowlist", () => {
      const res = validateTargetOrigin("https://unapproved-staging.internal", false, [
        "https://approved-staging.internal",
      ]);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("custom destination is not in the approved origin allowlist");
      expect(res.error).not.toContain("unapproved-staging.internal");
    });

    it("accepts custom targets present in the explicit allowlist", () => {
      const res = validateTargetOrigin("https://approved-staging.internal/api/investigate", false, [
        "https://approved-staging.internal",
      ]);
      expect(res.valid).toBe(true);
      expect(res.origin).toBe("https://approved-staging.internal");
    });
  });

  describe("Secret Sanitization & Information Security", () => {
    it("redacts explicit secrets, tokens, DB URLs, and passwords", () => {
      const raw = `Error with key: ${dummyAdminKey} and conn postgresql://user:pass@ep-pooler.neon.tech/neondb?sslmode=require`;
      const sanitized = sanitizeSecrets(raw, [dummyAdminKey]);

      expect(sanitized).not.toContain(dummyAdminKey);
      expect(sanitized).not.toContain("pass@ep-pooler");
      expect(sanitized).toContain("[REDACTED]");
    });

    it("redacts Bearer tokens in headers or strings", () => {
      const raw = "Header Authorization: Bearer abc123def456xyz789";
      expect(sanitizeSecrets(raw)).toBe("Header Authorization: Bearer [REDACTED]");
    });

    it("redacts userinfo embedded in URLs", () => {
      const raw = "Connecting to https://admin:super_secret_pw@db.internal:5432";
      expect(sanitizeSecrets(raw)).toBe("Connecting to https://[REDACTED]:[REDACTED]@db.internal:5432");
    });

    it("safely handles non-string, empty, or multiline inputs without throwing", () => {
      expect(sanitizeSecrets("")).toBe("");
      expect(sanitizeSecrets(undefined as unknown as string)).toBe("");
      expect(sanitizeSecrets("line 1\nline 2")).toBe("line 1\nline 2");
    });

    it("parses valid JSON without leaking raw body", () => {
      const parsed = parseJsonResponse('{"status":"ok"}', 200, "Test Step");
      expect(parsed).toEqual({ status: "ok" });
    });

    it("throws sanitized non-leaking error on invalid non-JSON payload", () => {
      expect(() => {
        parseJsonResponse("<html><title>502 Bad Gateway</title><body>Internal proxy text</body></html>", 502, "POST Step");
      }).toThrow("POST Step returned non-JSON payload (HTTP 502).");
    });
  });

  describe("Configuration & Opt-In Gates", () => {
    it("refuses to make any requests if confirmOptIn is false", async () => {
      const mockFetch = vi.fn();

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: false,
        fetchFn: mockFetch,
      });

      expect(result.success).toBe(false);
      expect(result.optedIn).toBe(false);
      expect(result.error).toContain("Opt-in required");
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("fails if baseUrl is missing or whitespace", async () => {
      const mockFetch = vi.fn();

      const result = await verifyProductionPersistence({
        baseUrl: "   ",
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
      });

      expect(result.success).toBe(false);
      expect(result.optedIn).toBe(true);
      expect(result.error).toContain("Target URL required");
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("fails if AHEADGUARD_ADMIN_KEY is missing or empty", async () => {
      const mockFetch = vi.fn();

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: "  ",
        confirmOptIn: true,
        fetchFn: mockFetch,
      });

      expect(result.success).toBe(false);
      expect(result.optedIn).toBe(true);
      expect(result.error).toContain("AHEADGUARD_ADMIN_KEY is required");
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe("End-to-End Success & Failure Modes", () => {
    const validInvestigationId = "inv_test_persistence_success_999";

    const createSampleReport = (marker: string) => ({
      investigationId: validInvestigationId,
      timestamp: "2026-10-28T22:30:00.000Z",
      originalUrl: "text://message-analysis",
      normalizedUrl: "text://message-analysis",
      riskOutcome: "Low observed risk",
      threatLikelihood: "Low",
      consequenceImpact: "Low",
      persisted: true,
      storageMode: "persisted",
      scamIntelligence: {
        analysisMode: "message",
        messageExcerpt: `Probe test. Unique marker: [${marker}]. Harmless text-only verification test.`,
        companyIdentity: { status: "Unverified identity" },
      },
    });

    it("verifies persistence successfully when all 3 steps pass and marker matches", async () => {
      const mockFetch = vi.fn();
      let capturedMarker = "";

      // Step 1: POST
      mockFetch.mockImplementationOnce(async (_url, options) => {
        const body = JSON.parse(options.body);
        const match = body.input.match(/\[(aheadguard-persistence-probe-[^\]]+)\]/);
        capturedMarker = match ? match[1] : "dummy";
        return new Response(JSON.stringify({ report: createSampleReport(capturedMarker) }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      });

      // Step 2: Unauthenticated GET -> 401
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: "Unauthorized: administrator credentials required to access stored records." }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        )
      );

      // Step 3: Authenticated GET -> 200 with stored report containing marker
      mockFetch.mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ report: createSampleReport(capturedMarker) }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      });

      const logSpy = vi.fn();
      const warnSpy = vi.fn();

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: logSpy, warn: warnSpy, error: vi.fn() },
      });

      expect(result.success).toBe(true);
      expect(result.investigationId).toBe(validInvestigationId);
      expect(result.details?.storageMode).toBe("persisted");
      expect(result.details?.markerVerified).toBe(true);
      expect(result.details?.postStatus).toBe(200);
      expect(result.details?.unauthGetStatus).toBe(401);
      expect(result.details?.authGetStatus).toBe(200);

      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Verify redirect: "error" is enforced on all calls
      for (const call of mockFetch.mock.calls) {
        expect(call[1].redirect).toBe("error");
      }

      // Verify Step 2 unauthenticated (no Authorization header)
      expect(mockFetch.mock.calls[1][1].headers.Authorization).toBeUndefined();

      // Verify Step 3 authenticated
      expect(mockFetch.mock.calls[2][1].headers.Authorization).toBe(`Bearer ${dummyAdminKey}`);

      // Verify marker was confirmed in logs
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("Unique marker verified in stored record"));
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("immutability"));
    });

    it("fails when retrieved stored report does not contain the unique test marker", async () => {
      const mockFetch = vi.fn();

      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: createSampleReport("some-other-marker-12345") }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );

      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );

      // Authenticated read returns report without the probe marker
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            report: {
              ...createSampleReport("different-marker-from-prior-run"),
              scamIntelligence: {
                messageExcerpt: "Standard text without probe marker.",
              },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("retrieved record does not contain the unique test marker");
      expect(result.details?.markerVerified).toBe(false);
    });

    it("fails safely when fetch encounters an unexpected redirect (redirect: error)", async () => {
      const mockFetch = vi.fn().mockImplementation(() => {
        return Promise.reject(new TypeError("Failed to fetch: redirect encountered"));
      });

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Security violation: unexpected redirect encountered");
    });

    it("fails when POST /api/investigate returns network timeout", async () => {
      const mockFetch = vi.fn().mockImplementation(() => {
        const err = new Error("The operation was aborted");
        err.name = "AbortError";
        return Promise.reject(err);
      });

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        timeoutMs: 100,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Request timed out after 100ms");
    });

    it("fails when POST /api/investigate returns HTTP 500 error without leaking server internals", async () => {
      const mockFetch = vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Internal Database Pool Error" }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        })
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("POST /api/investigate failed with HTTP 500");
      expect(result.details?.postStatus).toBe(500);
    });

    it("fails when POST /api/investigate returns ephemeral storage mode (database unconfigured)", async () => {
      const mockFetch = vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            report: {
              ...createSampleReport("probe-marker-123"),
              persisted: false,
              storageMode: "ephemeral",
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("report storageMode is 'ephemeral' (persisted: false)");
      expect(result.error).toContain("The production database is unconfigured or unable to persist records");
      expect(result.details?.storageMode).toBe("ephemeral");
    });

    it("fails security gate if unauthenticated read does not return HTTP 401 Unauthorized", async () => {
      const mockFetch = vi.fn();

      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: createSampleReport("marker-1") }), { status: 200 })
      );

      // Unauthenticated GET erroneously returns 200 (auth bypass)
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: createSampleReport("marker-1") }), { status: 200 })
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Security check failed: unauthenticated read of investigation returned HTTP 200, expected HTTP 401 Unauthorized");
      expect(mockFetch).toHaveBeenCalledTimes(2); // Aborts before Step 3
    });

    it("fails if admin authentication is rejected by server with HTTP 401", async () => {
      const mockFetch = vi.fn();

      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: createSampleReport("marker-1") }), { status: 200 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Admin authentication failed: server rejected the provided AHEADGUARD_ADMIN_KEY with HTTP 401");
      expect(result.details?.authGetStatus).toBe(401);
    });

    it("fails if persisted record is not found (HTTP 404) during authenticated retrieval", async () => {
      const mockFetch = vi.fn();

      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: createSampleReport("marker-1") }), { status: 200 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Not Found" }), { status: 404 })
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Persisted record was not found in the database (HTTP 404)");
      expect(result.details?.authGetStatus).toBe(404);
    });

    it("never leaks admin key even if network error contains the secret token", async () => {
      const mockFetch = vi.fn().mockImplementation(() => {
        return Promise.reject(new Error(`Failed connection using secret=${dummyAdminKey}`));
      });

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).not.toContain(dummyAdminKey);
      expect(result.error).toContain("[REDACTED]");
    });
  });

  describe("CLI Entrypoint & Flag Safety", () => {
    it("returns exit code 0 and prints help when invoked with --help", async () => {
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const code = await runCli(["--help"]);

      expect(code).toBe(0);
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("AheadGuard AI — Production Persistence Verification Probe"));
      // Verify --key is NOT mentioned in help output
      const allOutput = logSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(allOutput).not.toContain("--key=");
    });

    it("returns exit code 1 and blocks execution if legacy --key argument is passed", async () => {
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      const code = await runCli(["--key=secret123"]);

      expect(code).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Security violation: The --key command-line argument has been removed for security."));
    });

    it("returns exit code 1 if --prod is combined with a conflicting --url", async () => {
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      const code = await runCli(["--confirm-live-persistence", "--prod", "--url=https://evil.internal"]);

      expect(code).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Target conflict: --prod cannot be combined with a conflicting --url"));
    });

    it("returns exit code 0 and prints skip notice when invoked without opt-in flag", async () => {
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const code = await runCli([]);

      expect(code).toBe(0);
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("SKIPPED: Live production persistence verification requires explicit operator opt-in."));
    });
  });
});
