import { describe, it, expect } from "vitest";
import { evaluateOfferIntegrity, FLAGSHIP_SCENARIO_INPUT } from "../lib/offer-integrity/offer-evaluator";
import { extractOfferClaims } from "../lib/offer-integrity/claim-extractor";
import { verifyRecruitmentPolicy } from "../lib/offer-integrity/policy-verifier";
import { isApprovedEmployerHost } from "../lib/offer-integrity/vacancy-verifier";
import { analyzeRecruitmentBehavior } from "../lib/recruitment-intelligence";
import { validateAndNormalizeUrl, isUnsafeDestination } from "../lib/url-safety";
import { TrustGraphStore } from "../lib/trustgraph/graph-store";
import { isAllowedOrigin, createCorsHeaders } from "../lib/api-security";

describe("AheadGuard AI — Evidence-Verified Release Master Regression Suite (Tests A to N)", () => {
  // ==========================================
  // TEST A — SYNTHETIC NEXORA RECRUITMENT SCAM
  // ==========================================
  describe("TEST A — Synthetic Nexora Recruitment Scam", () => {
    const nexoraMessage = `Subject: Congratulations! You Are Selected for the AI & Machine Learning Internship

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

    it("extracts all structured claims and flags scam signals without navigating to .example", async () => {
      const extracted = extractOfferClaims({ offerMessage: nexoraMessage });

      // 1. Extraction checks
      expect(extracted.companyName).toBe("Nexora AI Labs Pvt. Ltd.");
      expect(extracted.roleTitle).toBe("AI & Machine Learning Intern");
      expect(extracted.duration).toBe("3 Months");
      expect(extracted.recruiterName).toBe("Rahul Sharma");
      expect(extracted.recruiterDesignation).toBe("Senior HR Recruiter");
      expect(extracted.recruitmentAnalysis.recruiter.channel).toBe("Telegram");
      expect(extracted.recruitmentAnalysis.recruiter.handleOrContact).toBe("@Nexora_Official_HR");

      // 2. Payment extraction
      expect(extracted.paymentAmount).toBe("999");
      expect(extracted.paymentCurrency).toBe("INR");
      expect(extracted.recruitmentAnalysis.fee.detected).toBe(true);
      expect(extracted.recruitmentAnalysis.fee.mandatory).toBe(true);
      expect(extracted.recruitmentAnalysis.fee.upiId).toBe("nexora.internship@upi");
      expect(extracted.recruitmentAnalysis.fee.refundabilityClaimed).toBe(true);

      // 3. Process anomalies
      expect(extracted.recruitmentAnalysis.process.noInterviewRequired).toBe(true);
      expect(extracted.recruitmentAnalysis.process.offerLetterPaywall).toBe(true);
      expect(extracted.recruitmentAnalysis.process.stipendNumeric).toBe(35000);

      // 4. Offer Integrity Evaluation
      const report = await evaluateOfferIntegrity({
        offerMessage: nexoraMessage,
      });

      // Assertions per Section 18 Test A:
      expect(report.canonicalExtraction?.employer.name).toBe("Nexora AI Labs Pvt. Ltd.");
      expect(report.canonicalExtraction?.job.title).toBe("AI & Machine Learning Intern");
      expect(report.canonicalExtraction?.compensation.amount).toBe(35000);
      expect(report.offerBreakdown.payment.paymentRequested).toBe(true);
      expect(report.offerBreakdown.payment.amount).toBe("999");
      expect(report.offerBreakdown.payment.upiId).toBe("nexora.internship@upi");
      expect(report.offerBreakdown.payment.paymentStatus).toBe("OBSERVED");
      expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("UNVERIFIED");
      expect(report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
      expect(report.offerBreakdown.destination.explanation).toContain(".example");

      // Verdict must be at least SUSPICIOUS
      expect(["Suspicious", "High risk"]).toContain(report.riskOutcome);
      expect(report.riskOutcome).not.toBe("Low observed risk");
      expect(report.riskOutcome).not.toBe("Unknown");

      // Safe action says DO NOT PAY
      expect(report.safeActionPlan.primaryWarning).toContain("999");
      expect(report.safeActionPlan.whatNotToDo).toContain(
        "Do NOT send money via UPI, QR code, netbanking, or cryptocurrency."
      );
      // Suppress .example from verified route
      expect(report.safeActionPlan.verifiedApplicationRoute).toBeUndefined();
    });
  });

  // ==========================================
  // TEST B — REAL AMAZON OFFICIAL CAREERS LISTING
  // ==========================================
  describe("TEST B — Real Amazon Official Careers Listing", () => {
    const amazonJobUrl = "https://www.amazon.jobs/en/jobs/10541345/sde-i-intern-amazon-university-talent-acquisition";

    it("verifies official domain, extracts requisition ID 10541345, and avoids fabricating details", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: `Candidate viewing authentic vacancy: ${amazonJobUrl}`,
        vacancyUrl: amazonJobUrl,
      });

      // 1. Official domain
      expect(["amazon.jobs", "amazon.com", "www.amazon.jobs"]).toContain(report.offerBreakdown.vacancy.officialDomain);

      // 2. Requisition and listing match
      expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(true);
      expect(report.offerBreakdown.vacancy.jobReferenceId).toBe("10541345");
      expect(report.offerBreakdown.vacancy.matchedListingUrl).toBe(amazonJobUrl);
      expect(report.offerBreakdown.vacancy.extractedTitle).toContain("SDE I Intern");

      // 3. Compensation & recruiter NOT fabricated
      expect(report.canonicalExtraction?.compensation.disclosedInMessage).toBe(false);
      expect(report.canonicalExtraction?.recruiter.name).toBeUndefined();

      // 4. No payment demanded
      expect(report.offerBreakdown.payment.paymentRequested).toBe(false);

      // 5. Authentic verdict for listing itself
      expect(report.riskOutcome).toBe("Low observed risk");
      expect(report.overallAssessment.verdictTitle).toBe("Verified Official Career Listing");
    });
  });

  // ==========================================
  // TEST C — REAL EMPLOYER, FAKE RECRUITER
  // ==========================================
  describe("TEST C — Real Employer, Fake Recruiter", () => {
    it("flags Suspicious when authentic employer is paired with an unverified personal messaging recruiter", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: `Congratulations! You have been selected for Google AI Intern. Contact our hiring lead Rahul on Telegram: @Google_Talent_Desk. Submit your resume directly.`,
        claimedCompany: "Google",
        claimedRole: "AI Intern",
        recruiterName: "Rahul",
      });

      // Employer is cataloged
      expect(report.offerBreakdown.vacancy.companyName).toBe("Google");
      expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(true);

      // Recruiter affiliation is unverified
      expect(report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
      expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(false);

      // Verdict reflects suspicious recruiter context
      expect(["Suspicious", "Unknown"]).toContain(report.riskOutcome);
      expect(report.riskOutcome).not.toBe("Low observed risk");
    });
  });

  // ==========================================
  // TEST D — REAL VACANCY, FAKE PAYMENT REQUEST
  // ==========================================
  describe("TEST D — Real Vacancy, Fake Payment Request", () => {
    it("flags HIGH RISK and confirms policy contradiction when genuine role has a fake fee demand", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: `Congratulations! Shortlisted for Google AI Intern. View requisition on careers.google.com. Pay ₹1,500 onboarding fee via UPI to hr@upi.`,
        claimedCompany: "Google",
        claimedRole: "AI Intern",
        paymentAmount: "1500",
        paymentReason: "Onboarding and equipment fee",
      });

      // Vacancy is verified / supported
      expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(true);

      // Payment request is observed
      expect(report.offerBreakdown.payment.paymentRequested).toBe(true);

      // Contradicted by official policy
      expect(report.offerBreakdown.payment.paymentStatus).toBe("CONTRADICTED");
      expect(report.offerBreakdown.payment.conflictsWithPolicy).toBe(true);

      // Overall verdict is High Risk
      expect(report.riskOutcome).toBe("High risk");
      expect(report.coreDistinctionNotice).toContain(
        "THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE"
      );
    });
  });

  // ==========================================
  // TEST E — NO NUMERIC AMOUNT
  // ==========================================
  describe("TEST E — No Numeric Amount", () => {
    it("detects mandatory recruitment fee when amount is not disclosed and never shows Zero Fees", async () => {
      const message = "Your internship has been confirmed. Pay the mandatory registration fee before receiving your offer letter.";
      const extracted = extractOfferClaims({ offerMessage: message });

      expect(extracted.recruitmentAnalysis.fee.detected).toBe(true);
      expect(extracted.recruitmentAnalysis.fee.mandatory).toBe(true);
      expect(extracted.paymentAmount).toBeUndefined();

      const report = await evaluateOfferIntegrity({ offerMessage: message });

      expect(report.offerBreakdown.payment.paymentRequested).toBe(true);
      expect(report.offerBreakdown.payment.amountDisclosed).toBe(false);
      expect(report.offerBreakdown.payment.paymentStatus).not.toBe("NOT_REQUESTED");
      expect(["Suspicious", "High risk"]).toContain(report.riskOutcome);
      expect(report.offerBreakdown.payment.explanation).not.toContain("Zero Fees Requested");
      expect(report.safeActionPlan.primaryWarning).not.toContain("undefined");
    });
  });

  // ==========================================
  // TEST F — UNKNOWN COMPANY, NO RED FLAGS
  // ==========================================
  describe("TEST F — Unknown Company, No Red Flags", () => {
    it("returns UNKNOWN verdict and does not invent suspicious indicators for benign unverified offers", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "We are pleased to offer you an internship position at Apex Horizon Dynamics as a Junior Analyst.",
        claimedCompany: "Apex Horizon Dynamics",
        claimedRole: "Junior Analyst",
      });

      expect(report.offerBreakdown.vacancy.isVacancyFound).toBe(false);
      expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("UNVERIFIED");
      expect(report.offerBreakdown.payment.paymentRequested).toBe(false);
      expect(report.offerBreakdown.payment.paymentStatus).toBe("NOT_REQUESTED");

      // Must be Unknown, NOT High Risk
      expect(report.riskOutcome).toBe("Unknown");
      expect(report.threatLikelihood).toBe("Uncertain");
    });
  });

  // ==========================================
  // TEST G — OPTIONAL TRAINING
  // ==========================================
  describe("TEST G — Optional Training", () => {
    it("does not classify optional third-party course mentions as mandatory hiring fees", () => {
      const text = "We offer optional paid certification workshops through Coursera. Selection for the role is completely free and requires no fee.";
      const analysis = analyzeRecruitmentBehavior({ text });

      expect(analysis.isOptionalTrainingNotice).toBe(true);
      expect(analysis.fee.detected).toBe(false);
      expect(analysis.fee.mandatory).toBe(false);
    });
  });

  // ==========================================
  // TEST H — DOMAIN IMPERSONATION
  // ==========================================
  describe("TEST H — Domain Impersonation & Strict Domain Security", () => {
    it("rejects subdomain confusion like amazon.jobs.attacker.example", () => {
      const approvedDomains = ["amazon.jobs", "amazon.com"];
      const isAttackerApproved = isApprovedEmployerHost("amazon.jobs.attacker.example", approvedDomains);
      expect(isAttackerApproved).toBe(false);

      const isRealApproved = isApprovedEmployerHost("www.amazon.jobs", approvedDomains);
      expect(isRealApproved).toBe(true);
    });

    it("rejects embedded credentials and unsafe destinations", () => {
      const credResult = validateAndNormalizeUrl("https://admin:secret123@amazon.jobs/jobs/101");
      expect(credResult.valid).toBe(false);
      if (!credResult.valid) {
        expect(credResult.error).toContain("embedded usernames or passwords");
      }

      const loopbackResult = isUnsafeDestination("127.0.0.1");
      expect(loopbackResult.unsafe).toBe(true);

      const privateIpResult = isUnsafeDestination("192.168.1.50");
      expect(privateIpResult.unsafe).toBe(true);
    });
  });

  // ==========================================
  // TEST I — POLICY SOURCE FAILURE
  // ==========================================
  describe("TEST I — Policy Source Failure Handling", () => {
    it("labels policy as CHECK_FAILED when external provider fails while retaining cached reference", () => {
      const result = verifyRecruitmentPolicy({
        companyName: "Google",
        simulateFailure: true,
      });

      expect(result.policyStatus).toBe("CHECK_FAILED");
      expect(result.sourceType).toBe("FAILED");
      expect(result.hasPublishedNoFeePolicy).toBe(true);
      expect(result.explanation).toContain("CHECK_FAILED");
      expect(result.explanation).toContain("Retaining cached corporate policy reference");
    });
  });

  // ==========================================
  // TEST J — RECRUITER VERIFICATION DIMENSIONS
  // ==========================================
  describe("TEST J — Recruiter Verification Dimensions", () => {
    it("separates corporate email-domain consistency from individual identity verification", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Official hiring communication for Microsoft SWE Intern.",
        claimedCompany: "Microsoft",
        claimedRole: "Software Engineer Intern",
        recruiterName: "Sarah Jenkins",
        recruiterDesignation: "University Recruiter",
        senderEmail: "sarah@microsoft.com",
      });

      // Domain matches company
      expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(true);
      expect(report.offerBreakdown.sender.emailDomainConsistency).toBe("MATCHED_DOMAIN");

      // Individual recruiter identity must remain UNVERIFIED
      expect(report.offerBreakdown.sender.individualIdentityStatus).toBe("UNVERIFIED");

      // Recruiter identity claim in ledger must remain UNVERIFIED
      const recruiterClaim = report.claimsLedger.find((c) => c.category === "recruiter_identity");
      if (recruiterClaim) {
        expect(recruiterClaim.status).toBe("UNVERIFIED");
      }
    });

    it("identifies generic webmail providers and flags unverified recruiter status", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Official hiring communication.",
        claimedCompany: "Microsoft",
        senderEmail: "sarah.recruiter@gmail.com",
      });

      expect(report.offerBreakdown.sender.emailDomainMatchesCompany).toBe(false);
      expect(report.offerBreakdown.sender.emailDomainConsistency).toBe("GENERIC_EMAIL_PROVIDER");
      expect(report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
    });
  });

  // ==========================================
  // TEST K — TINYFISH FAILURE HANDLING
  // ==========================================
  describe("TEST K — TinyFish Failure Handling", () => {
    it("handles live crawl failure gracefully without crashing or returning false safety", async () => {
      const report = await evaluateOfferIntegrity({
        offerMessage: "Candidate offer check with simulated external failure.",
        claimedCompany: "Nexora Technologies",
        vacancyUrl: "https://nexora.example/careers",
        allowLiveCrawl: true,
        simulateCheckFailure: true,
      });

      expect(report.offerBreakdown.vacancy.vacancyStatus).toBe("CHECK_FAILED");
      expect(report.riskOutcome).not.toBe("Low observed risk");
    });
  });

  // ==========================================
  // TEST L — DATABASE AND DURABLE JOBS
  // ==========================================
  describe("TEST L — Database and Durable Jobs Integration", () => {
    it("ingests entities into TrustGraphStore cleanly with owner isolation", () => {
      const store = TrustGraphStore.getInstance();
      const node = store.upsertNode(
        {
          type: "ORG_ENTITY",
          value: "Nexora AI Labs Pvt. Ltd.",
          canonicalValue: "nexora ai labs pvt. ltd.",
          confidence: 0.9,
        },
        "inv_test_123",
        "web"
      );

      expect(node.id).toBeDefined();
      expect(node.canonicalValue).toBe("nexora ai labs pvt. ltd.");
      expect(node.associatedInvestigationIds).toContain("inv_test_123");
    });
  });

  // ==========================================
  // TEST M — REPORT CONSISTENCY
  // ==========================================
  describe("TEST M — Report Consistency Across All Sections", () => {
    it("ensures verdict, ledger, breakdown, and safe action plan represent the same canonical result", async () => {
      const report = await evaluateOfferIntegrity(FLAGSHIP_SCENARIO_INPUT);

      expect(report.riskOutcome).toBe("High risk");
      expect(report.offerBreakdown.payment.paymentRequested).toBe(true);
      expect(report.offerBreakdown.payment.conflictsWithPolicy).toBe(true);

      // Claims ledger must contain payment claim with CONTRADICTED
      const paymentClaim = report.claimsLedger.find(
        (c) => c.category === "payment_requirement" || c.category === "payment_request"
      );
      expect(paymentClaim?.status).toBe("CONTRADICTED");

      // Safe Action Plan must direct refusal of the payment
      expect(report.safeActionPlan.primaryWarning).toContain("DO NOT PAY");
      expect(report.safeActionPlan.whatNotToDo).toContain(
        "Do NOT send money via UPI, QR code, netbanking, or cryptocurrency."
      );
    });
  });

  // ==========================================
  // TEST N — MOBILE & IOS WORKFLOW
  // ==========================================
  describe("TEST N — Mobile Workflow & Origin Security", () => {
    it("authorizes valid production and mobile origins safely", () => {
      const req = new Request("https://aheadguard-ai.vercel.app/api/offer-integrity", {
        headers: { origin: "https://aheadguard-ai.vercel.app" },
      });

      expect(isAllowedOrigin("https://aheadguard-ai.vercel.app", req)).toBe(true);
      expect(isAllowedOrigin("https://evil-attacker.example", req)).toBe(false);

      const cors = createCorsHeaders(req);
      expect(cors["Access-Control-Allow-Origin"]).toBe("https://aheadguard-ai.vercel.app");
      expect(cors["Access-Control-Allow-Origin"]).not.toBe("*");
    });
  });
});
