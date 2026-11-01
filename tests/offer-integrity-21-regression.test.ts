import { describe, it, expect } from "vitest";
import { evaluateOfferIntegrity } from "../lib/offer-integrity/offer-evaluator";
import { extractOfferClaims } from "../lib/offer-integrity/claim-extractor";
import { analyzeRecruitmentBehavior } from "../lib/recruitment-intelligence";

describe("Offer Integrity Intelligence 2.1 — Master Regression Suite", () => {
  const testAMessage = `Subject: Congratulations! You Are Selected for the AI & Machine Learning Internship

Hello Candidate,

Congratulations!

We are pleased to inform you that you have been selected for the AI & Machine Learning Internship at Nexora AI Labs.

Your profile has been shortlisted for our remote internship program.

Internship Details:

Company: Nexora AI Labs Pvt. Ltd.
Position: AI & Machine Learning Intern
Duration: 3 Months
Work Mode: 100% Remote
Monthly Stipend: ₹35,000

Mandatory Onboarding Confirmation:

To reserve your internship seat, you must complete a refundable registration and onboarding payment of ₹999.

This payment covers employee verification, internship registration, training access and digital offer letter generation.

Important:

1. Payment must be completed within 2 hours.
2. Only candidates who complete payment will receive their offer letter.
3. No interview is required.
4. The ₹999 amount will be refunded with your first month's stipend.
5. Failure to pay within the deadline will result in cancellation of your selection.

Payment Method: UPI
UPI ID: nexora.internship@upi
Amount: ₹999

Recruitment Coordinator:
Rahul Sharma
Senior HR Recruiter
Telegram: @Nexora_Official_HR

Application portal:
https://nexora-ai.example/internship`;

  const testBAmazonUrl =
    "https://www.amazon.jobs/en/jobs/10541345/sde-i-intern-amazon-university-talent-acquisition";

  // ==========================================
  // SECTION 1: TEST A — SYNTHETIC FRAUDULENT INTERNSHIP
  // ==========================================
  describe("Test A: Synthetic Fraudulent Internship (Nexora AI Labs Pvt. Ltd.)", () => {
    it("extracts all structured claims from message when form fields are empty", () => {
      const extracted = extractOfferClaims({
        offerMessage: testAMessage,
        claimedCompany: "",
        claimedRole: "",
        recruiterName: "",
        paymentAmount: "",
      });

      // 1. Employer Identification
      expect(extracted.companyName).toBe("Nexora AI Labs Pvt. Ltd.");
      expect(extracted.companyName).not.toBe("Unknown Employer");

      // 2. Role Identification
      expect(extracted.roleTitle).toBe("AI & Machine Learning Intern");
      expect(extracted.duration).toBe("3 Months");
      expect(extracted.workMode).toBe("100% Remote");

      // 3. Recruiter Identification
      expect(extracted.recruiterName).toBe("Rahul Sharma");
      expect(extracted.recruiterDesignation).toBe("Senior HR Recruiter");
      expect(extracted.recruitmentAnalysis.recruiter.channel).toBe("Telegram");
      expect(extracted.recruitmentAnalysis.recruiter.handleOrContact).toBe("@Nexora_Official_HR");

      // 4. Payment Demand
      expect(extracted.paymentAmount).toBe("999");
      expect(extracted.paymentCurrency).toBe("INR");
      expect(extracted.paymentChannel).toBe("UPI");
      expect(extracted.recruitmentAnalysis.fee.upiId).toBe("nexora.internship@upi");
      expect(extracted.recruitmentAnalysis.fee.refundabilityClaimed).toBe(true);

      // 5. Process Anomalies
      expect(extracted.recruitmentAnalysis.process.noInterviewRequired).toBe(true);
      expect(extracted.recruitmentAnalysis.process.offerLetterPaywall).toBe(true);
      expect(extracted.recruitmentAnalysis.process.stipendNumeric).toBe(35000);

      // 6. Canonical Extraction Baseline
      expect(extracted.canonicalExtraction).toBeDefined();
      expect(extracted.canonicalExtraction?.employer.name).toBe("Nexora AI Labs Pvt. Ltd.");
      expect(extracted.canonicalExtraction?.job.title).toBe("AI & Machine Learning Intern");
      expect(extracted.canonicalExtraction?.compensation.amount).toBe(35000);
      expect(extracted.canonicalExtraction?.payment.upiId).toBe("nexora.internship@upi");
      expect(extracted.canonicalExtraction?.selection.interviewRequired).toBe(false);
      expect(extracted.canonicalExtraction?.selection.paymentRequiredForOfferLetter).toBe(true);
    });

    it("evaluates offer integrity and produces at least SUSPICIOUS verdict with clear fee warning", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: testAMessage,
      });

      // Risk outcome must reflect the detected payment demand
      expect(["Suspicious", "High risk"]).toContain(report.riskOutcome);
      expect(report.riskOutcome).not.toBe("Low observed risk");
      expect(report.riskOutcome).not.toBe("Unknown");

      // Verification breakdown
      expect(report.offerBreakdown.vacancy.companyName).toBe("Nexora AI Labs Pvt. Ltd.");
      expect(report.offerBreakdown.vacancy.roleTitle).toBe("AI & Machine Learning Intern");
      expect(report.offerBreakdown.payment.paymentRequested).toBe(true);
      expect(report.offerBreakdown.payment.amount).toBe("999");
      expect(report.offerBreakdown.payment.paymentChannel).toBe("UPI");
      expect(report.offerBreakdown.sender.claimedRecruiterName).toBe("Rahul Sharma");

      // Canonical extraction returned in report
      expect(report.canonicalExtraction).toBeDefined();
      expect(report.canonicalExtraction?.employer.name).toBe("Nexora AI Labs Pvt. Ltd.");

      // Safety plan directive
      expect(report.safeActionPlan.primaryWarning).toContain("999");
      expect(report.safeActionPlan.whatNotToDo).toContain(
        "Do NOT send money via UPI, QR code, netbanking, or cryptocurrency."
      );
    });
  });

  // ==========================================
  // SECTION 2: TEST B — REAL AMAZON INTERNSHIP
  // ==========================================
  describe("Test B: Real Amazon Internship Listing", () => {
    it("corroborates authentic public listing, requisition ID, and avoids fabricating details", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: `Here is the official listing: ${testBAmazonUrl}`,
        vacancyUrl: testBAmazonUrl,
      });

      // 1. Employer verification
      expect(report.offerBreakdown.vacancy.companyName).toBe("Amazon");
      expect(report.offerBreakdown.vacancy.officialDomain).toBe("amazon.com");

      // 2. Requisition and listing match
      expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(true);
      expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("SUPPORTED");
      expect(report.offerBreakdown.vacancy.jobReferenceId).toBe("10541345");
      expect(report.offerBreakdown.vacancy.matchedListingUrl).toBe(testBAmazonUrl);

      // 3. Compensation & recruiter NOT fabricated
      expect(report.canonicalExtraction?.compensation.disclosedInMessage).toBe(false);
      expect(report.canonicalExtraction?.compensation.status).toBe("NOT_DISCLOSED_IN_LISTING");
      expect(report.canonicalExtraction?.recruiter.name).toBeUndefined();

      // 4. No payment demanded
      expect(report.offerBreakdown.payment.paymentRequested).toBe(false);

      // 5. Authentic verdict
      expect(report.riskOutcome).toBe("Low observed risk");
      expect(report.overallAssessment.verdictTitle).toBe("Verified Official Career Listing");
    });
  });

  // ==========================================
  // SECTION 3: 18 SYSTEMATIC REGRESSION EDGE CASES
  // ==========================================
  describe("Systematic Edge Cases (Section 10)", () => {
    // 1. Core Principle: Genuine vacancy weaponized for scam fee
    it("1. Flags High Risk when genuine employer vacancy is paired with a scam payment request", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: `Congratulations! Shortlisted for Google AI Intern. View requisition on careers.google.com. Pay ₹1,500 onboarding fee via UPI to hr@upi.`,
        claimedCompany: "Google",
        claimedRole: "Software Engineering Intern",
        paymentAmount: "1500",
      });

      expect(report.riskOutcome).toBe("High risk");
      expect(report.coreDistinctionNotice).toContain(
        "THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE"
      );
      expect(report.offerBreakdown.payment.conflictsWithPolicy).toBe(true);
    });

    // 2. Empty string form fields do not overwrite message-extracted values
    it("2. Does not overwrite message-extracted company when form field is empty string", () => {
      const extracted = extractOfferClaims({
        offerMessage: "Company: Nexora AI Labs Pvt. Ltd.\nPosition: Data Science Intern",
        claimedCompany: "",
        claimedRole: "",
      });

      expect(extracted.companyName).toBe("Nexora AI Labs Pvt. Ltd.");
      expect(extracted.roleTitle).toBe("Data Science Intern");
    });

    // 3. External lookup failure generates CHECK_FAILED, not UNVERIFIED or absence claim
    it("3. Distinguishes CHECK_FAILED when external lookup fails", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Checking role at Microsoft",
        claimedCompany: "Microsoft",
        claimedRole: "Explorer Intern",
        simulateCheckFailure: true,
      });

      expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("CHECK_FAILED");
      expect(report.offerBreakdown.vacancy.lookupStatus).toBe("FAILED");
      expect(report.offerBreakdown.vacancy.explanation).toContain("External lookup failed");
    });

    // 4. Fallback when extraction completely fails
    it("4. Shows 'Could not extract this field' when no company or role is mentioned", () => {
      const extracted = extractOfferClaims({
        offerMessage: "Hello, please find the document attached for your review.",
      });

      expect(extracted.companyName).toBeUndefined();
      expect(extracted.canonicalExtraction?.employer.name).toBe(
        "Could not extract this field — manual review required"
      );
    });

    // 5. Clean offer with zero fees yields paymentRequested: false
    it("5. Clean authentic message yields paymentRequested: false", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Interview scheduled for Tuesday at 10 AM on Google Meet. No fees or charges apply.",
        claimedCompany: "Google",
        claimedRole: "Software Engineer",
      });

      expect(report.offerBreakdown.payment.paymentRequested).toBe(false);
      expect(report.offerBreakdown.payment.paymentStatus).toBe("NOT_REQUESTED");
    });

    // 6. RFC 2606 .example domain recognized as synthetic
    it("6. Flags RFC 2606 .example domains in application URL", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Apply at https://careers.acme-corp.example/jobs",
      });

      expect(report.offerBreakdown.destination.explanation).toContain(".example");
      expect(report.canonicalExtraction?.application.domainClassification).toBe("SYNTHETIC_RESERVED");
    });

    // 7. Telegram recruiter handle detected and classified as personal messaging
    it("7. Identifies Telegram handle as personal unverified messaging channel", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "For details contact our HR on Telegram: @Acme_Recruitment",
      });

      expect(analysis.recruiter.channel).toBe("Telegram");
      expect(analysis.recruiter.handleOrContact).toBe("@Acme_Recruitment");
      expect(analysis.recruiter.isPersonalMessagingChannel).toBe(true);
    });

    // 8. WhatsApp phone contact detected and classified as personal messaging
    it("8. Identifies WhatsApp phone number as personal messaging channel", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "Please WhatsApp +91 9876543210 for interview slot confirmation",
      });

      expect(analysis.recruiter.channel).toBe("WhatsApp");
      expect(analysis.recruiter.isPersonalMessagingChannel).toBe(true);
    });

    // 9. Free webmail domain mismatch
    it("9. Flags generic Gmail address claiming to represent corporate brand", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Official offer from Google recruitment team.",
        claimedCompany: "Google",
        senderEmail: "google.recruiter2026@gmail.com",
      });

      expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(false);
      expect(report.offerBreakdown.sender.explanation).toContain("consumer email address (@gmail.com)");
    });

    // 10. Corporate email domain match
    it("10. Supports authenticated corporate email matching official domain", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Welcome to Google recruitment.",
        claimedCompany: "Google",
        senderEmail: "recruiter@google.com",
      });

      expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(true);
      expect(report.offerBreakdown.sender.affiliationStatus).toBe("SUPPORTED");
    });

    // 11. Urgency detection: 2-hour deadline
    it("11. Extracts strict urgency window from message", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "Failure to complete within 2 hours will cancel your seat.",
      });

      expect(analysis.urgency.detected).toBe(true);
      expect(analysis.urgency.deadlineText).toContain("within 2 hours");
    });

    // 12. Offer letter paywall detection
    it("12. Extracts condition where offer letter requires upfront payment", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "Only candidates who complete payment will receive their offer letter.",
      });

      expect(analysis.process.offerLetterPaywall).toBe(true);
    });

    // 13. Refundable fee lure detection
    it("13. Extracts refund promise as deceptive confidence trick", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "The ₹999 amount will be refunded with your first month's stipend.",
      });

      expect(analysis.fee.refundabilityClaimed).toBe(true);
    });

    // 14. Key-Value payment line parsing: "Amount: ₹999"
    it("14. Parses key-value structured payment line accurately", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "Payment Method: UPI\nAmount: ₹999\nRegistration Fee: ₹999",
      });

      expect(analysis.fee.detected).toBe(true);
      expect(analysis.fee.amount).toBe("999");
      expect(analysis.fee.numericAmount).toBe(999);
      expect(analysis.fee.currency).toBe("INR");
    });

    // 15. Key-Value role parsing: "Position: AI & Machine Learning Intern"
    it("15. Extracts role from 'Position:' key-value line", () => {
      const extracted = extractOfferClaims({
        offerMessage: "Company: Acme Corp\nPosition: AI & Machine Learning Intern",
      });

      expect(extracted.roleTitle).toBe("AI & Machine Learning Intern");
    });

    // 16. Monthly stipend parsing: "Monthly Stipend: ₹35,000"
    it("16. Extracts monthly stipend from key-value line", () => {
      const analysis = analyzeRecruitmentBehavior({
        text: "Monthly Stipend: ₹35,000",
      });

      expect(analysis.process.stipendUnverifiedLure).toBe(true);
      expect(analysis.process.stipendNumeric).toBe(35000);
      expect(analysis.process.stipendAmount).toBe("₹35,000");
    });

    // 17. Safe Action Plan contains explicit 'what NOT to do'
    it("17. Generates comprehensive Safe Action Plan with explicit warnings", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: testAMessage,
      });

      expect(report.safeActionPlan.stepByStepActions.length).toBeGreaterThanOrEqual(5);
      expect(report.safeActionPlan.whatNotToDo.length).toBeGreaterThanOrEqual(4);
      expect(
        report.safeActionPlan.whatNotToDo.some((item) =>
          item.toLowerCase().includes("upi")
        )
      ).toBe(true);
    });

    // 18. TrustGapMap nodes constructed for graph rendering
    it("18. Populates TrustGapMap nodes for visual graph representation", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: testAMessage,
      });

      expect(report.trustGapMapNodes.length).toBeGreaterThanOrEqual(5);
      const paymentNode = report.trustGapMapNodes.find((n) =>
        n.claim.toLowerCase().includes("payment") || n.claim.toLowerCase().includes("fee")
      );
      expect(paymentNode).toBeDefined();
    });
  });
});
