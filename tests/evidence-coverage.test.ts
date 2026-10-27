import { describe, it, expect } from "vitest";
import { calculateEvidenceCoverage } from "../lib/trust-gap";
import { DEMO_SCENARIO_A, DEMO_SCENARIO_B, DEMO_SCENARIO_C } from "../lib/demo-data";
import { InvestigationReport } from "../lib/types";

describe("Evidence Coverage & Quality Presentation", () => {
  it("computes comprehensive coverage for Scenario A with 100% supported claims", () => {
    const stats = calculateEvidenceCoverage(DEMO_SCENARIO_A);

    expect(stats.totalClaims).toBe(4);
    expect(stats.supportedCount).toBe(4);
    expect(stats.contradictedCount).toBe(0);
    expect(stats.unverifiedCount).toBe(0);
    expect(stats.completedChecksCount).toBe(5);
    expect(stats.coverageLevel).toBe("Comprehensive");
    expect(stats.hasFeeWarning).toBe(false);
    expect(stats.hasIdentityMismatch).toBe(false);
    expect(stats.keyFindings.some((k) => k.includes("verified against official records"))).toBe(true);
  });

  it("identifies high-risk contradiction indicators in Scenario B", () => {
    const stats = calculateEvidenceCoverage(DEMO_SCENARIO_B);

    expect(stats.totalClaims).toBe(4);
    expect(stats.contradictedCount).toBe(3);
    expect(stats.unverifiedCount).toBe(1);
    expect(stats.hasFeeWarning).toBe(true);
    expect(stats.hasIdentityMismatch).toBe(true);
    expect(stats.keyFindings.some((k) => k.includes("Recruitment fee demand detected"))).toBe(true);
    expect(stats.keyFindings.some((k) => k.includes("Domain does not match"))).toBe(true);
  });

  it("marks coverage as Inconclusive for Unknown risk reports (Scenario C)", () => {
    const stats = calculateEvidenceCoverage(DEMO_SCENARIO_C);

    expect(stats.coverageLevel).toBe("Inconclusive");
    expect(stats.unverifiedCount).toBe(3);
    expect(stats.supportedCount).toBe(0);
    expect(stats.hasFeeWarning).toBe(false);
  });

  it("handles empty claims array cleanly", () => {
    const blankReport: InvestigationReport = {
      investigationId: "empty-01",
      timestamp: "2026-10-27T12:00:00Z",
      originalUrl: "https://blank.test",
      normalizedUrl: "https://blank.test",
      observedDestination: {
        submittedUrl: "https://blank.test",
        normalizedUrl: "https://blank.test",
        submittedHost: "blank.test",
        destinationChanged: false,
        redirectChain: [],
      },
      checksPerformed: [],
      evidenceItems: [],
      observedFacts: {
        credentialOrPaymentRequest: false,
        downloadOrPermissionRequest: false,
        formsObserved: false,
        hasPasswordField: false,
        hasPaymentField: false,
        hasPunycode: false,
        isNumericIp: false,
        isHttp: false,
      },
      modelInterpretations: [],
      warningSigns: [],
      missingEvidence: [],
      actionPreview: {
        proposedAction: "None",
        consequenceIfProceed: "None",
        riskFactors: [],
      },
      riskOutcome: "Low observed risk",
      threatLikelihood: "Low",
      consequenceImpact: "Low",
      outcomeReason: "No data",
      recommendedAction: "None",
      limitations: [],
      eventsCount: 0,
    };

    const stats = calculateEvidenceCoverage(blankReport);
    expect(stats.totalClaims).toBe(0);
    expect(stats.supportedCount).toBe(0);
    expect(stats.contradictedCount).toBe(0);
    expect(stats.coverageLevel).toBe("Sparse");
  });
});
