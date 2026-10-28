import { describe, it, expect } from "vitest";
import { executeTinyFishInvestigation } from "../lib/tinyfish";
import { assessInvestigation } from "../lib/policy";
import { validateDatabaseHealthContract } from "../lib/db";

describe("AheadGuard Live Provider Smoke Test (TinyFish)", () => {
  const isEnabled = process.env.RUN_LIVE_SMOKE_TEST === "true";

  it.skipIf(!isEnabled)(
    "Executes live TinyFish investigation against a benign public website when explicitly enabled",
    async () => {
      const apiKey = process.env.TINYFISH_API_KEY?.trim();
      if (!apiKey || apiKey === "your_real_key_here" || apiKey === "your_tinyfish_api_key_here") {
        throw new Error(
          "TINYFISH_API_KEY is required to run live smoke test. Set a valid key in the environment or .env.local."
        );
      }

      const url = new URL("https://example.com");
      const result = await executeTinyFishInvestigation({
        url: url.toString(),
        apiKey,
      });

      expect(result).toBeDefined();
      expect(result.eventsCount).toBeGreaterThan(0);
      expect(result.success).toBe(true);
      expect(result.structuredResult).toBeDefined();

      const report = assessInvestigation({
        submittedUrl: url,
        tinyFishResult: result,
      });

      expect(report.investigationId).toBeDefined();
      expect(["Low observed risk", "Suspicious", "Unknown"]).toContain(report.riskOutcome);
    },
    120_000
  );
});

describe("AheadGuard Production Deployment Smoke Test (Vercel Live)", () => {
  const isEnabled = process.env.RUN_PROD_SMOKE_TEST === "true";
  const baseUrl = (process.env.PROD_URL || "https://aheadguard-ai.vercel.app").replace(/\/$/, "");

  it.skipIf(!isEnabled)(
    "Verifies health check and database status contract on live production endpoint",
    async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const res = await fetch(`${baseUrl}/api/investigate`, {
          signal: controller.signal,
          headers: { Accept: "application/json" },
        });
        expect(res.status).toBe(200);
        const data: unknown = await res.json();
        const validation = validateDatabaseHealthContract(data);
        expect(validation.valid).toBe(true);
        expect(["unconfigured", "connected", "unavailable"]).toContain(validation.status);
      } finally {
        clearTimeout(timeout);
      }
    },
    15_000
  );

  it.skipIf(!isEnabled)(
    "Verifies admin investigation history requires authorization and returns 401 without leakage",
    async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const res = await fetch(`${baseUrl}/api/investigate?action=history`, {
          signal: controller.signal,
          headers: { Accept: "application/json" },
        });
        expect(res.status).toBe(401);
        const data = (await res.json()) as { error?: string };
        expect(data.error).toBe("Unauthorized: administrator credentials required to access stored records.");
      } finally {
        clearTimeout(timeout);
      }
    },
    15_000
  );

  const isPostEnabled =
    process.env.RUN_LIVE_PROD_INVESTIGATION === "true" ||
    (process.env.RUN_PROD_SMOKE_TEST === "true" && process.env.RUN_LIVE_SMOKE_TEST === "true");

  /**
   * Note: This contract test verifies that the public POST investigation endpoint returns
   * a well-formed report and safely degrades to ephemeral mode when the database is unconfigured.
   * To strictly certify real write/read database persistence, use `npm run test:smoke:persistence`.
   */
  it.skipIf(!isPostEnabled)(
    "Verifies live public text analysis contract returns valid investigation report (authorized opt-in only)",
    async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 60_000);
      try {
        const res = await fetch(`${baseUrl}/api/investigate`, {
          method: "POST",
          signal: controller.signal,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: "Please inspect this link: https://example.com" }),
        });
        expect(res.status).toBe(200);
        const data = (await res.json()) as {
          report?: {
            investigationId?: string;
            riskOutcome?: string;
            storageMode?: string;
          };
        };
        expect(data).toHaveProperty("report");
        expect(data.report).toBeDefined();
        expect(data.report?.investigationId).toBeDefined();
        expect(["Low observed risk", "Suspicious", "Unknown"]).toContain(data.report?.riskOutcome);
        expect(["persisted", "ephemeral"]).toContain(data.report?.storageMode);
      } finally {
        clearTimeout(timeout);
      }
    },
    75_000
  );
});

/**
 * AheadGuard Strict Production Database Readiness Gate
 *
 * NOTE ON VERIFICATION SCOPE:
 * This strict smoke test verifies that the production database endpoint is reachable,
 * authenticated, and returning a valid health contract (status: "connected", ok: true).
 * It verifies connectivity and health contract readiness; it does NOT perform write/read
 * record persistence.
 *
 * To certify full end-to-end database persistence (write, unauthenticated 401 gate,
 * and authenticated read), execute the dedicated opt-in persistence verification probe:
 *   npm run test:smoke:persistence -- --confirm-live-persistence --prod
 */
describe("AheadGuard Strict Production Database Readiness Gate", () => {
  const isDbCheckEnabled = process.env.RUN_DB_SMOKE_TEST === "true";
  const baseUrl = (process.env.PROD_URL || "https://aheadguard-ai.vercel.app").replace(/\/$/, "");

  it.skipIf(!isDbCheckEnabled)(
    "Requires active database connectivity and verifies strict database readiness on production",
    async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const res = await fetch(`${baseUrl}/api/investigate`, {
          signal: controller.signal,
          headers: { Accept: "application/json" },
        });
        expect(res.status).toBe(200);
        const data: unknown = await res.json();
        const validation = validateDatabaseHealthContract(data, { strictConnected: true });
        if (!validation.valid) {
          throw new Error(validation.error);
        }
        expect(validation.valid).toBe(true);
        expect(validation.status).toBe("connected");
        expect(validation.ok).toBe(true);
      } finally {
        clearTimeout(timeout);
      }
    },
    15_000
  );
});
