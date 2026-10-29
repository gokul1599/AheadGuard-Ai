import { describe, it, expect } from "vitest";
import {
  evaluateAllClaims,
  generateIndependentVerificationRoutes,
  createTextOnlyReport,
} from "../lib/claims-evaluator";
import {
  sanitizeUrlForSharing,
  createShareableReport,
  formatReportMarkdown,
} from "../lib/share-report";
import { analyzeMessageText } from "../lib/message-intelligence";
import { verifyCompanyIdentity, verifyJobListing } from "../lib/company-verification";
import type { InvestigationReport } from "../lib/types";

describe("Claim Verification & Intelligence Sharing", () => {
  describe("evaluateAllClaims", () => {
    it("evaluates claims into Supported, Contradicted, and Unverified", () => {
      const msg = "Join Google as Software Engineer. Salary is $180,000/yr. Pay $50 registration fee to confirm.";
      const messageData = analyzeMessageText({ rawMessage: msg });
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com",
      });
      const jobVerification = verifyJobListing({
        claimedRole: "Software Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com",
        companyIdentity,
        feeWarningPresent: true,
      });

      const claims = evaluateAllClaims({
        initialClaims: messageData.claims,
        companyIdentity,
        jobVerification,
        targetUrl: "https://careers.google.com",
      });

      expect(claims.length).toBeGreaterThan(0);
      const feeClaim = claims.find((c) => c.category === "recruitment_fee");
      expect(feeClaim).toBeDefined();
      expect(feeClaim?.evaluation).toBe("Contradicted");

      const orgClaim = claims.find((c) => c.category === "employer_identity");
      expect(orgClaim).toBeDefined();
      expect(orgClaim?.evaluation).toBe("Supported");
    });
  });

  describe("generateIndependentVerificationRoutes", () => {
    it("provides direct careers and contact routes for verified brand without message links", () => {
      const companyIdentity = verifyCompanyIdentity({ claimedOrg: "Apple" });
      const routes = generateIndependentVerificationRoutes({
        companyIdentity,
        claimedRole: "Senior Engineer",
      });

      expect(routes.length).toBeGreaterThan(0);
      expect(routes.some((r) => r.routeType === "official_careers_page")).toBe(true);
      expect(routes.some((r) => r.url?.includes("apple.com"))).toBe(true);
    });
  });

  describe("createTextOnlyReport", () => {
    it("generates a complete structured report for pure text messages", () => {
      const msg = "Urgent: You are selected for Amazon Data Analyst role! Pay $100 security deposit to claim laptop. Reply via WhatsApp.";
      const messageData = analyzeMessageText({ rawMessage: msg });
      const companyIdentity = verifyCompanyIdentity({ claimedOrg: "Amazon" });
      const jobVerification = verifyJobListing({
        claimedRole: messageData.claimedJobRole,
        claimedEmployer: "Amazon",
        companyIdentity,
        feeWarningPresent: Boolean(messageData.recruitmentFeeWarning?.detected),
      });

      const report = createTextOnlyReport({
        messageData,
        companyIdentity,
        jobVerification,
      });

      expect(report.originalUrl).toBe("text://message-analysis");
      expect(["High risk", "Suspicious"]).toContain(report.riskOutcome);
      expect(report.scamIntelligence).toBeDefined();
      expect(report.scamIntelligence?.recruitmentFeeWarning?.detected).toBe(true);
      expect(report.scamIntelligence?.claims.length).toBeGreaterThan(0);
      expect(report.scamIntelligence?.independentVerificationRoutes.length).toBeGreaterThan(0);
    });

    it("evaluates real-world text-only recruitment fee demand as Suspicious with fee and payment warnings", () => {
      const msg = "Congratulations! You are shortlisted for Google Cloud Operations Lead. Salary is $12,000/month. To confirm your interview slot, please pay a refundable registration fee of $50 via UPI to recruitment.team@okaxis.";
      const messageData = analyzeMessageText({ rawMessage: msg });
      const companyIdentity = verifyCompanyIdentity({ claimedOrg: messageData.claimedOrganization });
      const jobVerification = verifyJobListing({
        claimedRole: messageData.claimedJobRole,
        claimedEmployer: messageData.claimedOrganization,
        companyIdentity,
        feeWarningPresent: Boolean(messageData.recruitmentFeeWarning?.detected),
      });

      const report = createTextOnlyReport({
        messageData,
        companyIdentity,
        jobVerification,
      });

      expect(report.riskOutcome).toBe("Suspicious");
      expect(report.threatLikelihood).toBe("Moderate");
      expect(report.scamIntelligence?.recruitmentFeeWarning?.detected).toBe(true);
      expect(report.scamIntelligence?.recruitmentFeeWarning?.feeType).toBe("application_fee");
      expect(report.scamIntelligence?.paymentRisks.some((r) => r.paymentType === "p2p_transfer")).toBe(true);
      expect(report.warningSigns.some((w) => w.includes("Recruitment Fee Demanded"))).toBe(true);
    });

    it("verifies legitimate Amazon job offer with official careers link (amazon.jobs) without identity mismatch", () => {
      const msg = "Amazon Talent Acquisition: We reviewed your profile for Senior Solutions Architect. Check the official requisition here: https://amazon.jobs";
      const messageData = analyzeMessageText({ rawMessage: msg });
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Amazon",
        destinationUrl: "https://amazon.jobs",
      });
      const jobVerification = verifyJobListing({
        claimedRole: "Senior Solutions Architect",
        claimedEmployer: "Amazon",
        jobListingUrl: "https://amazon.jobs",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(companyIdentity.status).toBe("Official domain match");
      expect(companyIdentity.isOfficialCorporateDomain).toBe(true);

      const claims = evaluateAllClaims({
        initialClaims: messageData.claims,
        companyIdentity,
        jobVerification,
        targetUrl: "https://amazon.jobs",
      });

      const employerClaim = claims.find((c) => c.category === "employer_identity");
      expect(employerClaim?.evaluation).toBe("Supported");
    });
  });

  describe("Privacy-Safe Sharing & URL Sanitization", () => {
    it("sanitizes tracking tokens, session IDs, and auth keys from URLs", () => {
      const dirtyUrl = "https://example.com/apply?token=secret_abc123&session_id=xyz789&utm_source=email&role=dev";
      const cleanUrl = sanitizeUrlForSharing(dirtyUrl);

      expect(cleanUrl).not.toContain("secret_abc123");
      expect(cleanUrl).not.toContain("token=");
      expect(cleanUrl).not.toContain("session_id=");
      expect(cleanUrl).toContain("role=dev");
      expect(cleanUrl).toContain("utm_source=email");
    });

    it("creates a shareable report with PII and sensitive URLs redacted", () => {
      const baseReport: InvestigationReport = {
        investigationId: "inv_share_test_123",
        timestamp: new Date().toISOString(),
        originalUrl: "https://example.com/portal?token=very_sensitive_token",
        normalizedUrl: "https://example.com/portal?token=very_sensitive_token",
        observedDestination: {
          submittedUrl: "https://example.com/portal?token=very_sensitive_token",
          normalizedUrl: "https://example.com/portal?token=very_sensitive_token",
          submittedHost: "example.com",
          destinationChanged: false,
          redirectChain: [],
        },
        riskOutcome: "Suspicious",
        threatLikelihood: "Moderate",
        consequenceImpact: "High",
        outcomeReason: "Contact recruiter at recruiter@scam.com or +1 555 123 4567 for details.",
        recommendedAction: "Do not send credentials or money.",
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
        warningSigns: ["Recruiter email was recruiter@scam.com"],
        missingEvidence: [],
        actionPreview: {
          proposedAction: "Reviewing link",
          consequenceIfProceed: "None",
          riskFactors: [],
        },
        limitations: [],
        eventsCount: 1,
      };

      const shareable = createShareableReport(baseReport);

      expect(shareable.originalUrl).not.toContain("very_sensitive_token");
      expect(shareable.outcomeReason).not.toContain("recruiter@scam.com");
      expect(shareable.outcomeReason).not.toContain("+1 555 123 4567");
      expect(shareable.outcomeReason).toContain("[EMAIL REDACTED]");
      expect(shareable.warningSigns[0]).toContain("[EMAIL REDACTED]");

      const markdown = formatReportMarkdown(shareable);
      expect(markdown).toContain("# AheadGuard AI — Trust & Verification Report");
      expect(markdown).toContain("SUSPICIOUS");
    });
  });
});
