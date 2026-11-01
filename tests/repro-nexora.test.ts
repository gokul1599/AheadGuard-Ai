import { describe, it, expect } from "vitest";
import { analyzeRecruitmentBehavior } from "../lib/recruitment-intelligence";
import { evaluateOfferIntegrity } from "../lib/offer-integrity/offer-evaluator";

describe("Recruitment Behavior Intelligence Engine", () => {
  const nexoraMessage = `Congratulations! You have been shortlisted for the AI & Machine Learning Internship at Nexora Technologies Pvt. Ltd.

Your internship duration will be 3 months, with a monthly stipend of ₹45,000.

To confirm your selection, you must complete mandatory employee verification by paying a refundable registration and onboarding fee of ₹2,999.

Payment must be completed within 24 hours through the UPI ID shared by your recruitment coordinator.

After payment confirmation, your digital offer letter and employee ID will be generated. No interview is required for this position.`;

  const nexoraParams = {
    text: nexoraMessage,
    claimedCompany: "Nexora Technologies Pvt. Ltd.",
    claimedRole: "AI & Machine Learning Intern — Work From Home",
    recruiterName: "Rahul Sharma — @Rahul_Nexora_HR (Telegram)",
    applicationUrl: "https://nexora-careers.example/ai-internship-apply",
    vacancyUrl: "https://nexora.example/careers",
  };

  it("extracts all structured recruitment scam patterns from Nexora input", () => {
    const analysis = analyzeRecruitmentBehavior(nexoraParams);

    expect(analysis.fee.detected).toBe(true);
    expect(analysis.fee.amount).toBe("2999");
    expect(analysis.fee.currency).toBe("INR");
    expect(analysis.fee.category).toBe("REGISTRATION_AND_ONBOARDING");
    expect(analysis.fee.mandatory).toBe(true);
    expect(analysis.fee.refundabilityClaimed).toBe(true);
    expect(analysis.fee.paymentMethod).toBe("UPI");
    expect(analysis.fee.classification).toBe("OBSERVED");

    expect(analysis.urgency.detected).toBe(true);
    expect(analysis.urgency.deadlineText).toMatch(/within 24 hours/i);
    expect(analysis.urgency.classification).toBe("OBSERVED");

    expect(analysis.process.noInterviewRequired).toBe(true);
    expect(analysis.process.offerLetterPaywall).toBe(true);
    expect(analysis.process.employeeIdPaywall).toBe(true);
    expect(analysis.process.stipendUnverifiedLure).toBe(true);

    expect(analysis.recruiter.channel).toBe("Telegram");
    expect(analysis.recruiter.handleOrContact).toBe("@Rahul_Nexora_HR");
    expect(analysis.recruiter.isPersonalMessagingChannel).toBe(true);

    expect(analysis.indicators.length).toBeGreaterThanOrEqual(5);
    const indNames = analysis.indicators.map((i) => i.indicator);
    expect(indNames).toContain("Upfront recruitment payment");
    expect(indNames).toContain("Payment urgency");
    expect(indNames).toContain("Selection without interview");
    expect(indNames).toContain("Recruiter identity");
    expect(indNames).toContain("Destination domain");

    console.log("RECRUITMENT INDICATORS:", JSON.stringify(analysis.indicators, null, 2));
  });

  it("evaluates Nexora offer through evaluateOfferIntegrity pipeline", async () => {
    const report = await evaluateOfferIntegrity({
      offerMessage: nexoraMessage,
      claimedCompany: nexoraParams.claimedCompany,
      claimedRole: nexoraParams.claimedRole,
      recruiterName: nexoraParams.recruiterName,
      applicationUrl: nexoraParams.applicationUrl,
      vacancyUrl: nexoraParams.vacancyUrl,
      paymentAmount: "2999",
      paymentReason: "Registration and onboarding fee",
    });

    console.log("FULL NEXORA EVALUATION REPORT:");
    console.log(JSON.stringify(report, null, 2));

    expect(["Suspicious", "High risk"]).toContain(report.riskOutcome);
    expect(report.claimsLedger.length).toBeGreaterThan(0);
  });
});
