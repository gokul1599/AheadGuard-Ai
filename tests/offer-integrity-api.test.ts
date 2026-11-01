import { describe, it, expect } from "vitest";
import { GET, POST, OPTIONS } from "../app/api/offer-integrity/route";
import { FLAGSHIP_SCENARIO_INPUT } from "../lib/offer-integrity/offer-evaluator";

describe("Offer Integrity API Endpoints (/api/offer-integrity)", () => {
  it("OPTIONS returns 204 with CORS headers", async () => {
    const req = new Request("http://localhost:3000/api/offer-integrity", {
      method: "OPTIONS",
      headers: { Origin: "http://localhost:3000" },
    });
    const res = await OPTIONS(req);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
  });

  it("GET returns metadata, flagship scenario, and policy directory stats", async () => {
    const req = new Request("http://localhost:3000/api/offer-integrity", {
      method: "GET",
      headers: { Origin: "http://localhost:3000" },
    });
    const res = await GET(req);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(data.module).toContain("Offer Integrity Intelligence");
    expect(data.flagshipScenario).toBeDefined();
    expect(data.policyDirectorySize).toBeGreaterThan(5);
  });

  it("POST validates input and rejects short or empty offer messages with 400", async () => {
    const req = new Request("http://localhost:3000/api/offer-integrity", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "http://localhost:3000",
      },
      body: JSON.stringify({ offerMessage: "hi" }),
    });
    const res = await POST(req);
    expect(res.status).toBe(400);

    const data = await res.json();
    expect(data.error).toBeDefined();
  });

  it("POST executes investigation on the flagship scenario and returns structured report", async () => {
    const req = new Request("http://localhost:3000/api/offer-integrity", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "http://localhost:3000",
      },
      body: JSON.stringify(FLAGSHIP_SCENARIO_INPUT),
    });
    const res = await POST(req);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(data.report).toBeDefined();
    expect(data.report.riskOutcome).toBe("High risk");
    expect(data.report.offerBreakdown.vacancy.vacancyStatus).toBe("SUPPORTED");
    expect(data.report.offerBreakdown.payment.paymentStatus).toBe("CONTRADICTED");
    expect(data.report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
  });
});
