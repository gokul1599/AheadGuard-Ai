import { describe, it, expect } from "vitest";
import { InvestigationOrchestrator } from "../lib/orchestrator/investigation-orchestrator";

describe("Investigation Orchestrator — Central Intelligence Engine", () => {
  const orchestrator = InvestigationOrchestrator.getInstance();

  it("orchestrates text-only scam investigation with recruitment fee and payment trap", async () => {
    const result = await orchestrator.orchestrateInvestigation({
      investigationId: "inv_orch_001",
      userId: "user_test_1",
      sourcePlatform: "whatsapp",
      inputCategory: "job_offer",
      rawInput:
        "Congratulations! Shortlisted for Google Operations Lead. Pay $50 registration fee to hr.team@okaxis. Apply at https://careers-google-verify.top/apply",
      claimedOrganization: "Google",
      claimedJobRole: "Operations Lead",
      hasExplicitUserConsent: true,
      timestamp: new Date().toISOString(),
    });

    expect(result.investigationId).toBe("inv_orch_001");
    expect(result.sourcePlatform).toBe("whatsapp");
    expect(result.riskOutcome).toBe("High risk");
    expect(result.safeActionPlan.whatNotToDo.some((w) => w.includes("registration fee"))).toBe(true);

    // Verify TrustGraph nodes were created
    expect(result.trustGraph.nodes.length).toBeGreaterThanOrEqual(2);
    const domainNode = result.trustGraph.nodes.find((n) => n.type === "DOMAIN");
    expect(domainNode?.canonicalValue).toBe("careers-google-verify.top");
  });

  it("orchestrates payment screenshot inspection with spoof APK detection", async () => {
    const result = await orchestrator.orchestrateInvestigation({
      investigationId: "inv_orch_002",
      userId: "merchant_test_2",
      sourcePlatform: "universal_share",
      inputCategory: "payment_screenshot",
      rawInput: "Payment receipt scan",
      ocrText: "Payment Successful ₹10,000 sent to Scaler. UTR: 000000009999. Paytm Spoof Simulator v1.0.",
      claimedOrganization: "Scaler",
      hasExplicitUserConsent: true,
      timestamp: new Date().toISOString(),
    });

    expect(result.transactionTruth).toBeDefined();
    expect(result.transactionTruth?.isSpoofSuspected).toBe(true);
    expect(result.riskOutcome).toBe("Suspicious");
    expect(result.safeActionPlan.stepByStepGuidance.some((s) => s.includes("bank statement"))).toBe(true);
  });

  it("orchestrates deceptive refund QR investigation", async () => {
    const result = await orchestrator.orchestrateInvestigation({
      investigationId: "inv_orch_003",
      userId: "user_test_3",
      sourcePlatform: "telegram",
      inputCategory: "qr_code",
      rawInput: "upi://pay?pa=refund.agent@okhdfcbank&pn=Instant_Refund&am=2000&tn=Tax_Refund",
      qrPayload: "upi://pay?pa=refund.agent@okhdfcbank&pn=Instant_Refund&am=2000&tn=Tax_Refund",
      hasExplicitUserConsent: true,
      timestamp: new Date().toISOString(),
    });

    expect(result.qrInspection).toBeDefined();
    expect(result.qrInspection?.isCollectRequest).toBe(true);
    expect(result.riskOutcome).toBe("High risk");
    expect(result.safeActionPlan.stepByStepGuidance.some((s) => s.includes("Never enter your UPI PIN"))).toBe(true);
  });
});
