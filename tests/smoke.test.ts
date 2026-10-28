import { describe, it, expect } from "vitest";
import { executeTinyFishInvestigation } from "../lib/tinyfish";
import { assessInvestigation } from "../lib/policy";

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
        const data = (await res.json()) as { db?: { ok: boolean; status: string } };
        expect(data).toHaveProperty("db");
        expect(typeof data.db?.ok).toBe("boolean");
        expect(["unconfigured", "connected", "error"]).toContain(data.db?.status);
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

  it.skipIf(!isEnabled)(
    "Verifies live public text analysis contract returns valid investigation report",
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
