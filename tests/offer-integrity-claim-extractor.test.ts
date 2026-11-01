import { describe, it, expect } from "vitest";
import { extractOfferClaims } from "../lib/offer-integrity/claim-extractor";

describe("Offer Integrity Claim Extractor", () => {
  it("extracts company, role, fee, and recruiter from unstructured offer text", () => {
    const text =
      "Congratulations! You have been shortlisted for an internship in our AI department at Google. Your role is listed on our careers portal. Pay ₹999 to reserve your interview slot via UPI. Contact Priya Sharma, Campus Recruiter at priya.recruiter@gmail.com.";
    const result = extractOfferClaims({ offerMessage: text });

    expect(result.companyName).toBe("Google");
    expect(result.roleTitle).toMatch(/AI/i);
    expect(result.paymentAmount).toBe("999");
    expect(result.paymentCurrency).toBe("INR");
    expect(result.recruiterName).toBe("Priya Sharma");
    expect(result.recruiterDesignation).toBe("Campus Recruiter");
    expect(result.senderEmail).toBe("priya.recruiter@gmail.com");
    expect(result.isShortlistedClaim).toBe(true);

    // Verify generated claim ledger items
    expect(result.claims.length).toBeGreaterThanOrEqual(4);
    const feeClaim = result.claims.find((c) => c.category === "payment_requirement");
    expect(feeClaim).toBeDefined();
    expect(feeClaim?.extractedValue).toContain("INR 999");
  });

  it("handles alternative currency formats and fees ($50, INR 1500, Rs. 2000)", () => {
    const textUsd = "Please pay a registration fee of $150 to reserve your laptop.";
    const resUsd = extractOfferClaims({ offerMessage: textUsd });
    expect(resUsd.paymentAmount).toBe("150");
    expect(resUsd.paymentCurrency).toBe("USD");

    const textInr = "Transfer INR 2,500 for training deposit.";
    const resInr = extractOfferClaims({ offerMessage: textInr });
    expect(resInr.paymentAmount).toBe("2500");
    expect(resInr.paymentCurrency).toBe("INR");
  });

  it("prefers explicit user-supplied fields over text regex extraction", () => {
    const text = "Internship offer from unknown department. Pay 500.";
    const result = extractOfferClaims({
      offerMessage: text,
      claimedCompany: "Microsoft Corporation",
      claimedRole: "Cloud Solution Architect Intern",
      paymentAmount: "999",
      recruiterName: "Alex Vance",
    });

    expect(result.companyName).toBe("Microsoft Corporation");
    expect(result.roleTitle).toBe("Cloud Solution Architect Intern");
    expect(result.paymentAmount).toBe("999");
    expect(result.recruiterName).toBe("Alex Vance");
  });

  it("detects urgency windows and artificial deadlines", () => {
    const text = "Urgent: You must pay ₹999 within 24 hours to confirm your interview.";
    const result = extractOfferClaims({ offerMessage: text });
    expect(result.urgencyText).toMatch(/within 24 hours/i);
    const urgencyClaim = result.claims.find((c) => c.category === "deadline_urgency");
    expect(urgencyClaim).toBeDefined();
  });
});
