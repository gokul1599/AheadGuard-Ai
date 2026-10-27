import { describe, it, expect } from "vitest";
import {
  verifyCompanyIdentity,
  verifyJobListing,
  isRecruitmentPlatform,
} from "../lib/company-verification";

describe("Company Identity & Job Verification Engine", () => {
  describe("isRecruitmentPlatform", () => {
    it("recognizes standard ATS and hiring platforms", () => {
      expect(isRecruitmentPlatform("https://boards.greenhouse.io/acme/jobs/123").isPlatform).toBe(true);
      expect(isRecruitmentPlatform("https://jobs.lever.co/initech/456").isPlatform).toBe(true);
      expect(isRecruitmentPlatform("https://acme.myworkdayjobs.com/en-US/careers").isPlatform).toBe(true);
      expect(isRecruitmentPlatform("https://jobs.smartrecruiters.com/company/role").isPlatform).toBe(true);
      expect(isRecruitmentPlatform("https://www.linkedin.com/jobs/view/999").isPlatform).toBe(true);
      expect(isRecruitmentPlatform("https://www.indeed.com/viewjob?jk=123").isPlatform).toBe(true);
      expect(isRecruitmentPlatform("https://internshala.com/internship/detail/123").isPlatform).toBe(true);
    });

    it("does not classify non-recruitment or arbitrary sites as recruitment platforms", () => {
      expect(isRecruitmentPlatform("https://example.com").isPlatform).toBe(false);
      expect(isRecruitmentPlatform("https://phishing-site.xyz/login").isPlatform).toBe(false);
      expect(isRecruitmentPlatform("https://docs.google.com/forms/d/e/123/viewform").isPlatform).toBe(false);
    });
  });

  describe("verifyCompanyIdentity", () => {
    it("recognizes Official Domain Match for verified brand registry domains", () => {
      const result = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/",
      });

      expect(result.status).toBe("Official domain match");
      expect(result.isOfficialCorporateDomain).toBe(true);
      expect(result.officialDomains).toContain("google.com");
      expect(result.explanation).toContain("google.com");
    });

    it("recognizes Third-Party Platform when claimed brand is hosted on an ATS", () => {
      const result = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://boards.greenhouse.io/google-cloud/jobs/12345",
      });

      expect(result.status).toBe("Third-party platform");
      expect(result.isThirdPartyPlatform).toBe(true);
      expect(result.explanation).toMatch(/greenhouse/i);
    });

    it("detects Identity Mismatch when brand token is used on an unaffiliated hostname", () => {
      const result = verifyCompanyIdentity({
        claimedOrg: "Microsoft",
        destinationUrl: "https://careers-microsoft-verification.com/login",
      });

      expect(result.status).toBe("Identity mismatch");
      expect(result.isOfficialCorporateDomain).toBe(false);
      expect(result.explanation).toMatch(/mismatch/i);
    });

    it("classifies shared free-hosting or forms as third-party platform with caution", () => {
      const result = verifyCompanyIdentity({
        claimedOrg: "Amazon",
        destinationUrl: "https://docs.google.com/forms/d/e/fake-form/viewform",
      });

      // Google Docs is not Amazon's official platform
      expect(["Third-party platform", "Identity mismatch"]).toContain(result.status);
    });

    it("returns Unverified Identity when no authoritative domain match exists", () => {
      const result = verifyCompanyIdentity({
        claimedOrg: "Acme Stealth Startup LLC",
        destinationUrl: "https://acme-stealth-random-site.biz/job",
      });

      expect(result.status).toBe("Unverified identity");
      expect(result.isOfficialCorporateDomain).toBe(false);
    });
  });

  describe("verifyJobListing", () => {
    it("reports Listing Matched when hosted on authentic recruitment platform or official domain", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/123",
      });

      const result = verifyJobListing({
        claimedRole: "Software Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/123",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(result.status).toBe("Listing matched");
      expect(result.explanation).toContain("careers.google.com");
    });

    it("reports Listing Contradicted when mandatory recruitment fees are requested", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/123",
      });

      const result = verifyJobListing({
        claimedRole: "Cloud Architect",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/123",
        companyIdentity,
        feeWarningPresent: true,
      });

      expect(result.status).toBe("Listing contradicted");
      expect(result.explanation).toMatch(/fee/i);
    });

    it("reports Listing Contradicted when identity mismatch is present", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Microsoft",
        destinationUrl: "https://careers-microsoft-verification.com/apply",
      });

      const result = verifyJobListing({
        claimedRole: "Frontend Developer",
        claimedEmployer: "Microsoft",
        jobListingUrl: "https://careers-microsoft-verification.com/apply",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(result.status).toBe("Listing contradicted");
      expect(result.explanation).toMatch(/mismatch/i);
    });

    it("reports Listing Not Found — Unverified without accusing entity when independent match is unavailable", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Apex Systems",
        destinationUrl: "https://apex-local-agency.net/contact",
      });

      const result = verifyJobListing({
        claimedRole: "Data Analyst",
        claimedEmployer: "Apex Systems",
        jobListingUrl: "https://apex-local-agency.net/contact",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(result.status).toBe("Listing not found — unverified");
      expect(result.explanation).not.toMatch(/fraudster|criminal/i);
    });
  });
});
