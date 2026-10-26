import { describe, it, expect } from "vitest";
import { executeTinyFishInvestigation } from "../lib/tinyfish";
import { assessInvestigation } from "../lib/policy";

describe("Optional Live Smoke Test", () => {
  const shouldRun =
    process.env.RUN_LIVE_SMOKE_TEST === "true" &&
    Boolean(process.env.TINYFISH_API_KEY) &&
    process.env.TINYFISH_API_KEY !== "your_real_key_here";

  it.skipIf(!shouldRun)(
    "Executes live TinyFish investigation against a benign public website when explicitly enabled",
    async () => {
      const url = new URL("https://example.com");
      const result = await executeTinyFishInvestigation({
        url: url.toString(),
        apiKey: process.env.TINYFISH_API_KEY!,
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
