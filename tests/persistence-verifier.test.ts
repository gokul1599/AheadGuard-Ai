import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  generatePersistenceMarker,
  buildHarmlessPersistencePayload,
  sanitizeSecrets,
  safeParseJsonResponse,
  verifyProductionPersistence,
  runCli,
} from "../scripts/verify-persistence.mjs";

describe("AheadGuard Production Persistence Verifier", () => {
  const dummyBaseUrl = "https://aheadguard-ai.vercel.app";
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

  describe("Secret Sanitization & Safe Response Parsing", () => {
    it("redacts explicit secrets from error messages and text strings", () => {
      const raw = `Error occurred with key: ${dummyAdminKey} and url postgresql://user:pass@ep-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`;
      const sanitized = sanitizeSecrets(raw, [dummyAdminKey]);

      expect(sanitized).not.toContain(dummyAdminKey);
      expect(sanitized).not.toContain("pass@ep-pooler");
      expect(sanitized).toContain("[REDACTED]");
    });

    it("redacts Bearer tokens in headers or logs", () => {
      const raw = "Request failed: Authorization: Bearer abc123def456xyz789";
      const sanitized = sanitizeSecrets(raw);

      expect(sanitized).toBe("Request failed: Authorization: Bearer [REDACTED]");
    });

    it("handles non-string or empty inputs safely", () => {
      expect(sanitizeSecrets("")).toBe("");
      expect(sanitizeSecrets(undefined as unknown as string)).toBe("");
    });

    it("parses valid JSON responses safely", async () => {
      const mockResponse = new Response(JSON.stringify({ ok: true, count: 42 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

      const parsed = await safeParseJsonResponse(mockResponse, "Test Step");
      expect(parsed).toEqual({ ok: true, count: 42 });
    });

    it("throws sanitized actionable error on non-JSON response body", async () => {
      const mockResponse = new Response("<html><head><title>502 Bad Gateway</title></head><body>502 Gateway Error</body></html>", {
        status: 502,
      });

      await expect(
        safeParseJsonResponse(mockResponse, "Vercel Gateway Probe")
      ).rejects.toThrow(/Vercel Gateway Probe returned invalid non-JSON payload \(HTTP 502\)/);
    });
  });

  describe("Configuration & Opt-In Gate", () => {
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

    it("fails if baseUrl has an invalid protocol", async () => {
      const mockFetch = vi.fn();

      const result = await verifyProductionPersistence({
        baseUrl: "ftp://aheadguard.internal",
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
      });

      expect(result.success).toBe(false);
      expect(result.optedIn).toBe(true);
      expect(result.error).toContain("Invalid target URL");
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
    const sampleReport = {
      investigationId: validInvestigationId,
      timestamp: "2026-10-28T22:30:00.000Z",
      originalUrl: "https://aheadguard-test.local/probe",
      normalizedUrl: "https://aheadguard-test.local/probe",
      riskOutcome: "Low observed risk",
      threatLikelihood: "Low",
      consequenceImpact: "Low",
      persisted: true,
      storageMode: "persisted",
    };

    it("verifies persistence successfully when all 3 steps pass", async () => {
      const mockFetch = vi.fn();

      // Step 1: POST /api/investigate -> 200 with persisted report
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: sampleReport }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );

      // Step 2: GET /api/investigate?id=... (unauthenticated) -> 401 Unauthorized
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: "Unauthorized: administrator credentials required to access stored records." }),
          {
            status: 401,
            headers: { "Content-Type": "application/json" },
          }
        )
      );

      // Step 3: GET /api/investigate?id=... (authenticated) -> 200 with matching report
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: sampleReport }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );

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
      expect(result.details?.postStatus).toBe(200);
      expect(result.details?.unauthGetStatus).toBe(401);
      expect(result.details?.authGetStatus).toBe(200);

      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Verify Step 1: POST
      const [postUrl, postOptions] = mockFetch.mock.calls[0];
      expect(postUrl).toBe(`${dummyBaseUrl}/api/investigate`);
      expect(postOptions.method).toBe("POST");
      expect(postOptions.headers["Content-Type"]).toBe("application/json");

      // Verify Step 2: Unauthenticated GET
      const [unauthUrl, unauthOptions] = mockFetch.mock.calls[1];
      expect(unauthUrl).toBe(`${dummyBaseUrl}/api/investigate?id=${validInvestigationId}`);
      expect(unauthOptions.headers.Authorization).toBeUndefined();

      // Verify Step 3: Authenticated GET
      const [authUrl, authOptions] = mockFetch.mock.calls[2];
      expect(authUrl).toBe(`${dummyBaseUrl}/api/investigate?id=${validInvestigationId}`);
      expect(authOptions.headers.Authorization).toBe(`Bearer ${dummyAdminKey}`);

      // Verify immutable ledger reminder was logged
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("immutability"));
    });

    it("fails when POST /api/investigate returns network timeout (AbortError)", async () => {
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

    it("fails when POST /api/investigate returns HTTP 500 error", async () => {
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
      expect(result.error).toContain("POST /api/investigate failed with HTTP 500: Internal Database Pool Error");
      expect(result.details?.postStatus).toBe(500);
    });

    it("fails when POST /api/investigate returns malformed JSON", async () => {
      const mockFetch = vi.fn().mockResolvedValueOnce(
        new Response("Server Crashed with NullPointer", { status: 200 })
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid non-JSON payload");
    });

    it("fails when POST /api/investigate response is missing report object", async () => {
      const mockFetch = vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true }), {
          status: 200,
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
      expect(result.error).toContain("missing 'report' object");
    });

    it("fails when POST /api/investigate returns invalid investigationId", async () => {
      const mockFetch = vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            report: {
              ...sampleReport,
              investigationId: "invalid/id/with/slashes",
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
      expect(result.error).toContain("invalid investigationId");
    });

    it("fails with actionable message when report storageMode is ephemeral (database unconfigured)", async () => {
      const mockFetch = vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            report: {
              ...sampleReport,
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
      expect(result.error).toContain("Persistence verification failed: report storageMode is 'ephemeral' (persisted: false)");
      expect(result.error).toContain("The production database is unconfigured or unable to persist records");
      expect(result.details?.storageMode).toBe("ephemeral");
      expect(result.details?.persisted).toBe(false);
    });

    it("fails security gate if unauthenticated read does not return HTTP 401 Unauthorized", async () => {
      const mockFetch = vi.fn();

      // Step 1: POST succeeds
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: sampleReport }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );

      // Step 2: Unauthenticated GET erroneously returns 200 (auth bypass!)
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: sampleReport }), {
          status: 200,
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
      expect(result.error).toContain("Security check failed: unauthenticated read of investigation");
      expect(result.error).toContain("returned HTTP 200, expected HTTP 401 Unauthorized");
      expect(result.details?.unauthGetStatus).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(2); // Aborts before Step 3
    });

    it("fails if admin authentication is rejected by server with HTTP 401", async () => {
      const mockFetch = vi.fn();

      // Step 1: POST succeeds
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: sampleReport }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      );

      // Step 2: Unauthenticated GET returns 401
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );

      // Step 3: Authenticated GET also returns 401 (invalid admin key on server)
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized: administrator credentials required." }), { status: 401 })
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
        new Response(JSON.stringify({ report: sampleReport }), { status: 200 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Investigation report not found." }), { status: 404 })
      );

      const result = await verifyProductionPersistence({
        baseUrl: dummyBaseUrl,
        adminKey: dummyAdminKey,
        confirmOptIn: true,
        fetchFn: mockFetch,
        logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("was not found in the database (HTTP 404). The write may not have committed");
      expect(result.details?.authGetStatus).toBe(404);
    });

    it("fails if retrieved record ID does not match the newly created investigation ID", async () => {
      const mockFetch = vi.fn();

      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ report: sampleReport }), { status: 200 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })
      );
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            report: {
              ...sampleReport,
              investigationId: "inv_different_id_9999",
            },
          }),
          { status: 200 }
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
      expect(result.error).toContain("Retrieved record ID 'inv_different_id_9999' does not match expected ID");
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

  describe("CLI Entrypoint", () => {
    it("returns exit code 0 and prints help when invoked with --help", async () => {
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const code = await runCli(["--help"]);

      expect(code).toBe(0);
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("AheadGuard AI — Production Persistence Verification Probe"));
    });

    it("returns exit code 0 and prints skip notice when invoked without opt-in flag", async () => {
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const code = await runCli([]);

      expect(code).toBe(0);
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("SKIPPED: Live production persistence verification requires explicit operator opt-in."));
    });
  });
});
