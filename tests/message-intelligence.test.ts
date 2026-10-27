import { describe, it, expect } from "vitest";
import {
  extractUrlsFromText,
  redactSensitivePii,
  detectRecruitmentFee,
  detectPaymentRisks,
  detectSensitiveDataRequests,
  analyzeMessageText,
} from "../lib/message-intelligence";

describe("Message Intelligence Engine", () => {
  describe("URL Extraction", () => {
    it("extracts a single clean URL from text", () => {
      const msg = "Congratulations! Please check the details at https://careers.google.com/jobs/123 to proceed.";
      const urls = extractUrlsFromText(msg);
      expect(urls).toEqual(["https://careers.google.com/jobs/123"]);
    });

    it("extracts multiple URLs and strips trailing punctuation", () => {
      const msg = "Check https://amazon.jobs, or review the offer at https://onboarding-portal.net/verify! Also visit www.google.com.";
      const urls = extractUrlsFromText(msg);
      expect(urls).toHaveLength(3);
      expect(urls).toContain("https://amazon.jobs/");
      expect(urls).toContain("https://onboarding-portal.net/verify");
      expect(urls).toContain("https://www.google.com/");
    });

    it("returns empty array when text contains no URLs", () => {
      const msg = "Hello, you have been selected for the Data Analyst role. Please reply to this message.";
      const urls = extractUrlsFromText(msg);
      expect(urls).toEqual([]);
    });
  });

  describe("PII Redaction Engine", () => {
    it("redacts email addresses, phone numbers, and OTP codes", () => {
      const msg = "Contact recruiter hr.smith@company.com or call +1 (555) 234-5678. Your OTP is 849201 for verification.";
      const { redactedText, redactions } = redactSensitivePii(msg);
      expect(redactedText).toContain("[EMAIL REDACTED]");
      expect(redactedText).toContain("[PHONE REDACTED]");
      expect(redactedText).toContain("[CODE REDACTED]");
      expect(redactedText).not.toContain("hr.smith@company.com");
      expect(redactedText).not.toContain("849201");
      expect(redactions.length).toBeGreaterThan(0);
    });

    it("redacts government IDs (Aadhaar, PAN, SSN) and card numbers", () => {
      const msg = "Send Aadhaar 1234 5678 9012, PAN ABCDE1234F, SSN 123-45-6789, and card 4111 2222 3333 4444.";
      const { redactedText } = redactSensitivePii(msg);
      expect(redactedText).not.toContain("1234 5678 9012");
      expect(redactedText).not.toContain("ABCDE1234F");
      expect(redactedText).not.toContain("123-45-6789");
      expect(redactedText).not.toContain("4111 2222 3333 4444");
      expect(redactedText).toContain("[GOV ID REDACTED]");
      expect(redactedText).toContain("[CARD NUMBER REDACTED]");
    });
  });

  describe("Recruitment Fee Detection", () => {
    it("detects upfront registration/application fee requests and quotes exact text", () => {
      const msg = "Congratulations on being shortlisted! You must pay a registration fee of ₹1,500 to secure your slot.";
      const warning = detectRecruitmentFee(msg);
      expect(warning).toBeDefined();
      expect(warning?.detected).toBe(true);
      expect(warning?.feeType).toBe("application_fee");
      expect(warning?.quotedText.toLowerCase()).toContain("registration fee");
      expect(warning?.riskLevel).toBe("High");
    });

    it("detects refundable security deposits", () => {
      const msg = "A refundable security deposit of $250 is required before laptop dispatch.";
      const warning = detectRecruitmentFee(msg);
      expect(warning).toBeDefined();
      expect(warning?.feeType).toBe("security_deposit");
      expect(warning?.quotedText).toContain("refundable security deposit");
    });

    it("detects mandatory training fees", () => {
      const msg = "Selected candidates must pay for mandatory training course fee before joining.";
      const warning = detectRecruitmentFee(msg);
      expect(warning).toBeDefined();
      expect(warning?.feeType).toBe("training_fee");
    });

    it("does NOT flag legitimate statements about candidate salary or remuneration", () => {
      const msg = "You will be paid a monthly stipend of $3,500 via direct deposit. Salary payments occur on the 1st.";
      const warning = detectRecruitmentFee(msg);
      expect(warning).toBeUndefined();
    });

    it("does NOT flag ordinary payment references in business terms", () => {
      const msg = "Our client payment terms are net 30 days after invoice submission.";
      const warning = detectRecruitmentFee(msg);
      expect(warning).toBeUndefined();
    });
  });

  describe("Payment Risks & Sensitive Data Requests", () => {
    it("detects personal UPI/P2P transfer instructions", () => {
      const msg = "Send money to UPI ID recruitment.team@okaxis to confirm your offer.";
      const risks = detectPaymentRisks(msg);
      expect(risks.some((r) => r.paymentType === "p2p_transfer")).toBe(true);
      expect(risks[0].quotedText).toContain("recruitment.team@okaxis");
    });

    it("detects password requests in message text", () => {
      const msg = "Please reply with your password and full name to activate your account.";
      const items = detectSensitiveDataRequests(msg);
      expect(items.some((i) => i.dataCategory === "password")).toBe(true);
    });

    it("detects OTP forwarding requests in message text", () => {
      const msg = "Share the OTP sent to your phone to complete your interview confirmation.";
      const items = detectSensitiveDataRequests(msg);
      expect(items.some((i) => i.dataCategory === "otp_2fa")).toBe(true);
    });

    it("does not flag informational mentions of password guidelines", () => {
      const msg = "Company security policy: Always use a strong password with at least 12 characters.";
      const items = detectSensitiveDataRequests(msg);
      expect(items).toHaveLength(0);
    });
  });

  describe("End-to-End analyzeMessageText", () => {
    it("correctly analyzes a scam job offer message", () => {
      const msg = `Dear candidate,
You have been selected for Software Development Intern at Microsoft.
Stipend: $5,000 per month.
Please pay an application fee of $150 at https://microsoft-careers-portal.cc/pay to receive your offer letter.
Send questions to hr@microsoft-portal.cc or call +1 555-019-2834.`;

      const result = analyzeMessageText({ rawMessage: msg });
      expect(result.claimedOrganization).toBe("Microsoft");
      expect(result.claimedJobRole?.toLowerCase()).toContain("software development intern");
      expect(result.claimedCompensation).toBeDefined();
      expect(result.recruitmentFeeWarning?.detected).toBe(true);
      expect(result.extractedUrls).toEqual(["https://microsoft-careers-portal.cc/pay"]);
      expect(result.appliedRedactions.length).toBeGreaterThan(0);
      expect(result.redactedText).toContain("[EMAIL REDACTED]");
      expect(result.redactedText).toContain("[PHONE REDACTED]");
    });
  });
});
