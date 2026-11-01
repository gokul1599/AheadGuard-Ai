import { describe, it, expect } from "vitest";
import { verifyRecruitmentPolicy, findEnterprisePolicy } from "../lib/offer-integrity/policy-verifier";

describe("Offer Integrity Recruitment Policy Verifier", () => {
  it("indexes verified enterprise no-fee policies for major employers", () => {
    const googlePolicy = findEnterprisePolicy("Google");
    expect(googlePolicy).toBeDefined();
    expect(googlePolicy?.hasPublishedNoFeePolicy).toBe(true);
    expect(googlePolicy?.policyQuote).toMatch(/never asks for money/i);

    const tcsPolicy = findEnterprisePolicy("TCS");
    expect(tcsPolicy).toBeDefined();
    expect(tcsPolicy?.hasPublishedNoFeePolicy).toBe(true);
    expect(tcsPolicy?.policyQuote).toMatch(/does not charge any fee/i);

    const msftPolicy = findEnterprisePolicy("Microsoft");
    expect(msftPolicy).toBeDefined();
    expect(msftPolicy?.policyQuote).toMatch(/does not request money/i);
  });

  it("returns POLICY_CONFIRMED_NO_FEE for cataloged employers", () => {
    const result = verifyRecruitmentPolicy({ companyName: "Amazon" });
    expect(result.policyStatus).toBe("POLICY_CONFIRMED_NO_FEE");
    expect(result.hasPublishedNoFeePolicy).toBe(true);
    expect(result.policyQuote).toContain("Amazon never asks for recruitment fees");
    expect(result.policyUrl).toMatch(/amazon\.jobs/);
  });

  it("detects no-fee declarations in observed webpage content dynamically", () => {
    const crawledSnippet = "Security Advisory: Acme Corp does not charge any application or interview fees.";
    const result = verifyRecruitmentPolicy({
      companyName: "Acme Corp",
      observedPageText: crawledSnippet,
      sourceUrl: "https://acme.example.com/careers",
    });

    expect(result.policyStatus).toBe("POLICY_CONFIRMED_NO_FEE");
    expect(result.hasPublishedNoFeePolicy).toBe(true);
    expect(result.policyQuote).toMatch(/does not charge any application or interview fees/i);
  });

  it("honestly preserves NO_POLICY_FOUND when no corporate policy exists without fabricating evidence", () => {
    const result = verifyRecruitmentPolicy({ companyName: "Random Startup XYZ 123" });
    expect(result.policyStatus).toBe("NO_POLICY_FOUND");
    expect(result.hasPublishedNoFeePolicy).toBe(false);
    expect(result.policyQuote).toBeUndefined();
    expect(result.explanation).toContain("No explicit recruitment anti-fraud or no-fee policy document was indexed");
  });
});
