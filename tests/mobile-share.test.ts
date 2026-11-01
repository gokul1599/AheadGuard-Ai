import { describe, it, expect, beforeEach } from "vitest";
import { POST } from "../app/api/mobile/share/route";
import { JobStore } from "../lib/jobs/job-store";

describe("AheadGuard AI 3.0 — Mobile OS Share Sheet Ingestion", () => {
  beforeEach(() => {
    JobStore.getInstance().resetForTesting();
  });

  const createShareRequest = (body: Record<string, unknown>, origin = "https://aheadguard-ai.vercel.app") => {
    return new Request("http://localhost:3000/api/mobile/share", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": origin,
      },
      body: JSON.stringify(body),
    });
  };

  it("processes Android SEND Intent with job offer text and returns Offer Integrity report", async () => {
    const payload = {
      platform: "android",
      sharedText:
        "Selected for Microsoft Internship! Pay ₹2,500 security deposit to UPI id msft-hr@okaxis. Contact hr@gmail.com",
      appVersion: "3.0.0",
      deviceModel: "Pixel 8 Pro",
      clientNonce: "nonce_android_123",
    };

    const req = createShareRequest(payload);
    const res = await POST(req);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(data.jobId).toBeDefined();
    expect(data.status).toBe("COMPLETED");
    expect(data.result?.type).toBe("offer");
    expect(data.result?.riskOutcome).toBe("High risk");
    expect(data.result?.report.offerBreakdown.vacancy.companyName).toBe("Microsoft");
    expect(data.result?.report.offerBreakdown.payment.paymentStatus).toBe("CONTRADICTED");
  });

  it("processes iOS Share Extension payload with suspicious URL and returns risk assessment", async () => {
    const payload = {
      platform: "ios",
      sharedUrl: "https://apple-id-verify-security.online/signin",
      appVersion: "3.0.0",
      deviceModel: "iPhone 15 Pro",
      clientNonce: "nonce_ios_456",
    };

    const req = createShareRequest(payload);
    const res = await POST(req);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(data.jobId).toBeDefined();
    expect(data.status).toBe("COMPLETED");
    expect(data.result?.type).toBe("standard");
    expect(["High risk", "Suspicious"]).toContain(data.result?.riskOutcome);
  });

  it("rejects malformed mobile share payloads missing both text and URL", async () => {
    const payload = {
      platform: "android",
      deviceModel: "Galaxy S24",
    };

    const req = createShareRequest(payload);
    const res = await POST(req);
    expect(res.status).toBe(400);

    const data = await res.json();
    expect(data.error).toBe("Invalid share payload");
  });
});
