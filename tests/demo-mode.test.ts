import { describe, it, expect } from "vitest";
import {
  DEMO_SCENARIOS,
  DEMO_SCENARIO_A,
  DEMO_SCENARIO_B,
  DEMO_SCENARIO_C,
  getDemoScenario,
  isDemoReport,
  DEMO_DISCLAIMER_BADGE,
  DEMO_DISCLAIMER_FULL,
} from "../lib/demo-data";
import { createShareableReport, formatReportMarkdown, formatReportSummary } from "../lib/share-report";
import { InvestigationReport } from "../lib/types";

describe("Instant Offline Demo Mode", () => {
  it("provides exactly 3 high-fidelity demonstration scenarios", () => {
    expect(DEMO_SCENARIOS).toHaveLength(3);
    const ids = DEMO_SCENARIOS.map((s) => s.id);
    expect(ids).toEqual(["scenario-a", "scenario-b", "scenario-c"]);
  });

  it("retrieves each scenario by id via getDemoScenario()", () => {
    const scenarioA = getDemoScenario("scenario-a");
    const scenarioB = getDemoScenario("scenario-b");
    const scenarioC = getDemoScenario("scenario-c");
    const unknownScenario = getDemoScenario("scenario-xyz");

    expect(scenarioA).toBeDefined();
    expect(scenarioA?.name).toContain("Verifiable Internship");
    expect(scenarioB).toBeDefined();
    expect(scenarioB?.name).toContain("Suspicious Recruitment");
    expect(scenarioC).toBeDefined();
    expect(scenarioC?.name).toContain("Ambiguous Offer");
    expect(unknownScenario).toBeUndefined();
  });

  it("identifies demo reports reliably via isDemoReport()", () => {
    expect(isDemoReport(DEMO_SCENARIO_A)).toBe(true);
    expect(isDemoReport(DEMO_SCENARIO_B)).toBe(true);
    expect(isDemoReport(DEMO_SCENARIO_C)).toBe(true);

    const liveReport: InvestigationReport = {
      investigationId: "live-inv-12345",
      timestamp: new Date().toISOString(),
      originalUrl: "https://example.com",
      normalizedUrl: "https://example.com",
      observedDestination: {
        submittedUrl: "https://example.com",
        normalizedUrl: "https://example.com",
        submittedHost: "example.com",
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
        proposedAction: "Browse",
        consequenceIfProceed: "None",
        riskFactors: [],
      },
      riskOutcome: "Low observed risk",
      threatLikelihood: "Low",
      consequenceImpact: "Low",
      outcomeReason: "No threat signals detected.",
      recommendedAction: "Proceed normally.",
      limitations: [],
      eventsCount: 1,
    };

    expect(isDemoReport(liveReport)).toBe(false);
    expect(isDemoReport(null)).toBe(false);
    expect(isDemoReport(undefined)).toBe(false);
  });

  describe("Scenario A: Verifiable Internship Offer", () => {
    it("has valid structure, low risk outcome, and verified corporate ATS signals", () => {
      expect(DEMO_SCENARIO_A.isDemo).toBe(true);
      expect(DEMO_SCENARIO_A.riskOutcome).toBe("Low observed risk");
      expect(DEMO_SCENARIO_A.threatLikelihood).toBe("Low");
      expect(DEMO_SCENARIO_A.consequenceImpact).toBe("Low");

      const intel = DEMO_SCENARIO_A.scamIntelligence;
      expect(intel).toBeDefined();
      expect(intel?.companyIdentity.status).toBe("Official domain match");
      expect(intel?.companyIdentity.isOfficialCorporateDomain).toBe(true);
      expect(intel?.jobVerification?.status).toBe("Listing matched");
      expect(intel?.jobVerification?.matchedListingUrl).toBeDefined();
      expect(intel?.recruitmentFeeWarning?.detected).toBe(false);

      // Verify all claims are supported
      const supportedClaims = intel?.claims.filter((c) => c.evaluation === "Supported") || [];
      expect(supportedClaims.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe("Scenario B: Suspicious Recruitment Offer (Fee Trap)", () => {
    it("detects advance recruitment fee, domain mismatch, and assigns High Risk", () => {
      expect(DEMO_SCENARIO_B.isDemo).toBe(true);
      expect(DEMO_SCENARIO_B.riskOutcome).toBe("High risk");
      expect(DEMO_SCENARIO_B.threatLikelihood).toBe("High");
      expect(DEMO_SCENARIO_B.consequenceImpact).toBe("High");

      const intel = DEMO_SCENARIO_B.scamIntelligence;
      expect(intel).toBeDefined();
      expect(intel?.companyIdentity.status).toBe("Identity mismatch");
      expect(intel?.jobVerification?.status).toBe("Listing not found — unverified");

      // Recruitment fee warning must be critical
      expect(intel?.recruitmentFeeWarning?.detected).toBe(true);
      expect(intel?.recruitmentFeeWarning?.feeType).toBe("security_deposit");
      expect(intel?.recruitmentFeeWarning?.quotedText).toContain("$120");

      // Payment risks & sensitive data requests must be populated
      expect(intel?.paymentRisks.length).toBeGreaterThanOrEqual(1);
      expect(intel?.sensitiveDataRequests.length).toBeGreaterThanOrEqual(2);

      // Contradicted claims
      const contradicted = intel?.claims.filter((c) => c.evaluation === "Contradicted") || [];
      expect(contradicted.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Scenario C: Ambiguous Offer (Inconclusive)", () => {
    it("assigns Unknown outcome without false safety guarantees", () => {
      expect(DEMO_SCENARIO_C.isDemo).toBe(true);
      expect(DEMO_SCENARIO_C.riskOutcome).toBe("Unknown");
      expect(DEMO_SCENARIO_C.threatLikelihood).toBe("Uncertain");

      const intel = DEMO_SCENARIO_C.scamIntelligence;
      expect(intel).toBeDefined();
      expect(intel?.companyIdentity.status).toBe("Unverified identity");
      expect(intel?.jobVerification?.status).toBe("Verification unavailable");
      expect(DEMO_SCENARIO_C.outcomeReason).toMatch(/inconclusive|cannot be treated as safe/i);

      // Claims are unverified
      const unverified = intel?.claims.filter((c) => c.evaluation === "Unverified") || [];
      expect(unverified.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Demo Exports & Disclaimers", () => {
    it("preserves isDemo and demoDisclaimer in createShareableReport()", () => {
      const shareableA = createShareableReport(DEMO_SCENARIO_A);
      expect(shareableA.isDemo).toBe(true);
      expect(shareableA.demoScenarioId).toBe("scenario-a");
      expect(shareableA.demoDisclaimer).toBe(DEMO_DISCLAIMER_FULL);

      const shareableB = createShareableReport(DEMO_SCENARIO_B);
      expect(shareableB.isDemo).toBe(true);
      expect(shareableB.demoDisclaimer).toBe(DEMO_DISCLAIMER_FULL);
    });

    it("includes prominent DEMO DATA banner in formatReportMarkdown()", () => {
      const md = formatReportMarkdown(DEMO_SCENARIO_B);
      expect(md).toContain(DEMO_DISCLAIMER_BADGE);
      expect(md).toContain("DEMO NOTE: Offline demonstration mode");
    });

    it("includes [DEMO DATA] prefix in formatReportSummary()", () => {
      const summary = formatReportSummary(DEMO_SCENARIO_A);
      expect(summary).toContain("[DEMO DATA — NOT A LIVE INVESTIGATION]");
      expect(summary).toContain("LOW OBSERVED RISK");
    });
  });
});
