import { describe, it, expect } from "vitest";
import {
  verifyCompanyIdentity,
  verifyJobListing,
  isRecruitmentPlatform,
  matchesRoleText,
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

    it("verifies user-provided careers URL only if hostname matches approved corporate domains", () => {
      const verifiedResult = verifyCompanyIdentity({
        claimedOrg: "Google",
        userProvidedCareersUrl: "https://careers.google.com/jobs/applications",
      });

      expect(verifiedResult.isUserProvidedCareersUrlVerified).toBe(true);
      expect(verifiedResult.candidateCareersUrl).toBe("https://careers.google.com/jobs/applications");
      expect(verifiedResult.officialCareersUrl).toBe("https://careers.google.com/jobs/applications");

      const unverifiedResult = verifyCompanyIdentity({
        claimedOrg: "Google",
        userProvidedCareersUrl: "https://fake-google-jobs.xyz/portal",
      });

      expect(unverifiedResult.isUserProvidedCareersUrlVerified).toBe(false);
      expect(unverifiedResult.candidateCareersUrl).toBe("https://fake-google-jobs.xyz/portal");
      // Must NOT be set to the fake user-provided careers URL! Fallback to registry or undefined
      expect(unverifiedResult.officialCareersUrl).toBe("https://careers.google.com/");
    });
  });

  describe("matchesRoleText", () => {
    it("rejects generic recruitment terms from falsely matching generic site headers", () => {
      expect(matchesRoleText("Intern", "Google Careers - Search Jobs & Internships")).toBe(false);
      expect(matchesRoleText("Job", "Google Jobs - Career Opportunities")).toBe(false);
      expect(matchesRoleText("Career Opening", "Careers Portal | Openings")).toBe(false);
    });

    it("requires whole word boundary matches and avoids substring collisions", () => {
      expect(matchesRoleText("Data Lead", "Database leaderboards and profiles")).toBe(false);
      expect(matchesRoleText("React Developer", "Proactive developer tools")).toBe(false);
    });

    it("matches specific substantive roles on authentic title text", () => {
      expect(matchesRoleText("Software Engineer", "Google Careers - Senior Software Engineer, Search")).toBe(true);
      expect(matchesRoleText("Cloud Security Architect", "Cloud Security Architect - Enterprise Systems")).toBe(true);
    });
  });

  describe("verifyJobListing", () => {
    it("does not treat an authentic corporate domain as proof of a specific vacancy without evidence", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/123",
      });

      const result = verifyJobListing({
        claimedRole: "Staff Site Reliability Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/123",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(result.status).toBe("Listing not found — unverified");
      expect(result.explanation).toContain("Employer domain recognized");
      expect(result.explanation).toContain("specific vacancy not independently verified");
    });

    it("reports Listing Matched when authentic platform is corroborated by direct evidence or page title", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/123",
      });

      const resultWithDirectEvidence = verifyJobListing({
        claimedRole: "Software Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/123",
        companyIdentity,
        feeWarningPresent: false,
        directEvidence: { roleMatched: true, vacancyConfirmed: true },
      });

      expect(resultWithDirectEvidence.status).toBe("Listing matched");
      expect(resultWithDirectEvidence.explanation).toContain("Software Engineer");

      const resultWithPageTitle = verifyJobListing({
        claimedRole: "Software Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/123",
        companyIdentity,
        feeWarningPresent: false,
        observedPageTitle: "Google Careers — Senior Software Engineer, Search Core",
      });

      expect(resultWithPageTitle.status).toBe("Listing matched");
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
