import { describe, it, expect } from "vitest";
import { evaluateOfferIntegrity, FLAGSHIP_SCENARIO_INPUT } from "../lib/offer-integrity/offer-evaluator";

describe("Offer Integrity Evaluator & Flagship Scenario", () => {
  it("executes the flagship scenario correctly: Role SUPPORTED, Fee CONTRADICTED, Sender UNVERIFIED", async () => {
    const report = await evaluateOfferIntegrity(FLAGSHIP_SCENARIO_INPUT);

    // 1. Core Principle Check
    expect(report.coreDistinctionNotice).toContain("THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE");

    // 2. Component 1: Vacancy is SUPPORTED on official careers portal
    expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("SUPPORTED");
    expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(true);
    expect(report.offerBreakdown.vacancy.matchedListingUrl).toBeDefined();

    // 3. Component 2: Fee is CONTRADICTED by published corporate policy
    expect(report.offerBreakdown.payment.paymentRequested).toBe(true);
    expect(report.offerBreakdown.payment.paymentStatus).toBe("CONTRADICTED");
    expect(report.offerBreakdown.payment.conflictsWithPolicy).toBe(true);
    expect(report.offerBreakdown.policy.policyStatus).toBe("POLICY_CONFIRMED_NO_FEE");
    expect(report.offerBreakdown.policy.policyQuote).toBeDefined();

    // 4. Component 3: Sender is UNVERIFIED (communicating from generic free consumer email)
    expect(report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
    expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(false);

    // 5. Deterministic Risk Outcome under 4-Tier policy: High risk
    expect(report.riskOutcome).toBe("High risk");
    expect(report.threatLikelihood).toBe("High");
    expect(report.consequenceImpact).toBe("Severe");

    // 6. Safe Action Plan guidance
    expect(report.safeActionPlan.primaryWarning).toContain("DO NOT PAY");
    expect(report.safeActionPlan.stepByStepActions.some((s) => s.includes("Refuse the payment"))).toBe(true);
    expect(report.safeActionPlan.verifiedApplicationRoute).toBeDefined();

    // 7. Trust Gap Map nodes integrity
    expect(report.trustGapMapNodes.length).toBeGreaterThanOrEqual(4);
    const vacancyNode = report.trustGapMapNodes.find((n) => n.id === "claim-offer-vacancy");
    expect(vacancyNode?.status).toBe("SUPPORTED");

    const paymentNode = report.trustGapMapNodes.find((n) => n.id === "claim-offer-payment");
    expect(paymentNode?.status).toBe("CONTRADICTED");

    // 8. Source Explorer references
    expect(report.sourceExplorer.length).toBeGreaterThanOrEqual(2);
    expect(report.sourceExplorer.some((s) => s.sourceCategory === "Official Careers Portal")).toBe(true);
    expect(report.sourceExplorer.some((s) => s.sourceCategory === "Recruitment Policy Page")).toBe(true);
  });

  it("evaluates a legitimate offer without payment demand as Low observed risk", async () => {
    const report = await evaluateOfferIntegrity({
      offerMessage: "We are pleased to offer you the position of Software Engineer Intern at Microsoft. Please review your offer letter on our candidate portal.",
      claimedCompany: "Microsoft",
      claimedRole: "Software Engineer Intern",
      recruiterName: "Sarah Jenkins",
      senderEmail: "sarah.jenkins@microsoft.com",
      vacancyUrl: "https://careers.microsoft.com/jobs/123",
      applicationUrl: "https://careers.microsoft.com/jobs/123",
    });

    expect(report.offerBreakdown.payment.paymentRequested).toBe(false);
    expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(true);
    expect(report.offerBreakdown.sender.affiliationStatus).toBe("SUPPORTED");
    expect(report.riskOutcome).toBe("Low observed risk");
  });

  it("evaluates an unverified company demanding fees with Suspicious outcome", async () => {
    const report = await evaluateOfferIntegrity({
      offerMessage: "Congratulations! You are selected for Remote Data Entry Internship at UnknownGlobalTech. Pay ₹499 for ID card verification.",
      claimedCompany: "UnknownGlobalTech",
      claimedRole: "Remote Data Entry Intern",
      paymentAmount: "499",
      senderEmail: "admin@unknownglobaltech.info",
    });

    expect(report.offerBreakdown.payment.paymentRequested).toBe(true);
    expect(report.offerBreakdown.policy.policyStatus).toBe("NO_POLICY_FOUND");
    // When no corporate policy is indexed, fee demand is flagged as Suspicious unverified fee
    expect(report.riskOutcome).toBe("Suspicious");
    expect(report.offerBreakdown.payment.cautionNotice).toContain("Never pay interview reservation fees");
  });

  it("Scenario B: Unverified vacancy without payment request returns Unknown (never Low observed risk)", async () => {
    const report = await evaluateOfferIntegrity({
      offerMessage: "Congratulations! You are invited to interview for Frontend Developer at UnregisteredStartup999.",
      claimedCompany: "UnregisteredStartup999",
      claimedRole: "Frontend Developer",
    });

    expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(false);
    expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("UNVERIFIED");
    expect(report.riskOutcome).toBe("Unknown");
    expect(report.overallAssessment.verdictTitle).toContain("Unverified Vacancy");
  });

  it("Scenario D: Genuine company but unverified sender with unsolicited selection returns Suspicious", async () => {
    const report = await evaluateOfferIntegrity({
      offerMessage: "Congratulations! You have been shortlisted for an Internship at Google without applying. Please send your resume to recruiter99@gmail.com.",
      claimedCompany: "Google",
      claimedRole: "Software Engineer Intern",
      senderEmail: "recruiter99@gmail.com",
    });

    expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(true);
    expect(report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
    expect(report.riskOutcome).toBe("Suspicious");
    expect(report.overallAssessment.verdictTitle).toContain("Unverified Contact");
  });
});
