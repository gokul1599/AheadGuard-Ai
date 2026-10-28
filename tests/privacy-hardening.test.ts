import { describe, it, expect } from "vitest";
import {
  createShareableReport,
  formatReportMarkdown,
  formatReportSummary,
  sanitizeUrlForSharing,
} from "../lib/share-report";
import { verifyCompanyIdentity, verifyJobListing } from "../lib/company-verification";
import { generateIndependentVerificationRoutes, evaluateAllClaims } from "../lib/claims-evaluator";
import type { InvestigationReport } from "../lib/types";

describe("Critical Privacy and Verification Accuracy Hardening", () => {
  describe("1. Shareable Report Sanitization & URL Redaction", () => {
    it("strips basic auth, sensitive query params, and token fragments from URLs", () => {
      const dirtyUrl =
        "https://admin:SuperSecretPass123!@company.internal/verify?token=eyJhGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0&public_ref=order_99#access_token=secret_jwt_fragment_abc";

      const cleaned = sanitizeUrlForSharing(dirtyUrl);
      expect(cleaned).not.toContain("admin");
      expect(cleaned).not.toContain("SuperSecretPass123!");
      expect(cleaned).not.toContain("eyJhGciOiJIUzI1NiJ9");
      expect(cleaned).not.toContain("secret_jwt_fragment_abc");
      expect(cleaned).toContain("public_ref=order_99");
      expect(cleaned).toContain("company.internal");
    });

    it("recursively redacts PII across all nested fields without mutating original report", () => {
      const originalReport: InvestigationReport = {
        investigationId: "inv-test-pii-001",
        timestamp: "2026-10-27T10:00:00Z",
        originalUrl: "https://user:pass@example.com/apply?token=secret_token_123#auth_token=jwt_fragment",
        normalizedUrl: "https://example.com/apply?token=secret_token_123#auth_token=jwt_fragment",
        observedDestination: {
          submittedUrl: "https://example.com/apply?token=secret_token_123",
          normalizedUrl: "https://example.com/apply?token=secret_token_123",
          submittedHost: "example.com",
          destinationChanged: false,
          redirectChain: [],
        },
        checksPerformed: [
          {
            name: "PII Check",
            status: "completed",
            detail: "Applicant SSN 123-45-6789 provided for verification along with email test.user@targetcorp.org",
          },
        ],
        evidenceItems: [
          {
            label: "Credit Card Observed",
            detail: "Payment form recorded card 4111-2222-3333-4444 and phone +1-555-234-5678",
            kind: "warning",
            provenance: "page_content",
          },
        ],
        observedFacts: {
          pageTitle: "Contact HR at hr-recruiter@victim.com or call 9876543210",
          visiblePurpose: "Wire funds to IBAN GB29XAAA14258324901234 or account 123456789012",
          credentialOrPaymentRequest: false,
          downloadOrPermissionRequest: false,
          formsObserved: false,
          hasPasswordField: false,
          hasPaymentField: false,
          hasPunycode: false,
          isNumericIp: false,
          isHttp: false,
        },
        modelInterpretations: [
          {
            aspect: "identity",
            interpretation: "Recipient identified as contact with PAN ABCDE1234F and Aadhaar 2345 6789 0123",
            confidence: "high",
          },
        ],
        warningSigns: ["Emergency wire to Account 987654321000 requested"],
        missingEvidence: ["No official confirmation for user 919876543210"],
        actionPreview: {
          proposedAction: "Send password MySecretPass#2026 to unlock job portal",
          consequenceIfProceed: "Reveals card 4111222233334444 to untrusted recipient",
          riskFactors: ["OTP 849201 requested over insecure channel"],
        },
        riskOutcome: "Suspicious",
        threatLikelihood: "High",
        consequenceImpact: "High",
        outcomeReason: "Recipient demanded upfront payment from card 4111 2222 3333 4444",
        recommendedAction: "Do not disclose SSN 987-65-4321 or send funds to account 5555444433332222",
        limitations: ["Observation limited to supplied link with token secret_abc_123"],
        eventsCount: 1,
        scamIntelligence: {
          analysisMode: "message",
          messageExcerpt: "Send ₹5000 to UPI pay-admin@okaxis or call 9876543210",
          extractedUrls: ["https://example.com/apply?token=leak_token_123#access_token=secret_jwt"],
          selectedTargetUrl: "https://example.com/apply",
          companyIdentity: {
            claimedOrganization: "Acme",
            status: "Unverified identity",
            explanation: "Contact John at john.doe@acme.com or 555-123-4567",
            isRegisteredBrand: false,
            isOfficialCorporateDomain: false,
            isThirdPartyPlatform: false,
            officialDomains: [],
            verifiedAt: "2026-10-27T10:00:00Z",
            evidenceSources: [
              {
                title: "Internal note",
                url: "https://example.com/info?token=internal_jwt#secret_hash",
                sourceType: "external_source",
                retrievedAt: "2026-10-27T10:00:00Z",
                snippet: "Applicant phone +44 7911 123456 verified",
              },
            ],
          },
          jobVerification: {
            claimedRole: "DevOps Engineer",
            claimedEmployer: "Acme",
            status: "Listing not found — unverified",
            explanation: "Job post claimed salary $120,000 via direct deposit to account 987654321098",
            checkedSources: [],
            verifiedAt: "2026-10-27T10:00:00Z",
            limitations: "Contact recruitment team at 9876543210",
          },
          recruitmentFeeWarning: {
            detected: true,
            quotedText: "Pay training fee of $250 to card 4111-2222-3333-4444",
            explanation: "Demanding fee violates recruitment norms",
            riskLevel: "High",
          },
          paymentRisks: [
            {
              id: "pr-1",
              paymentType: "fee_for_job",
              quotedText: "Transfer $500 to account 12345678901234",
              claimedRecipient: "Recruiter Bob (bob@scam.org)",
              cautionReason: "Never wire money to personal account",
              destinationInvestigated: true,
              evidenceSummary: "Bank routing 021000021 account 1234567890",
              recommendedVerificationStep: "Verify via official HR switchboard",
            },
          ],
          sensitiveDataRequests: [
            {
              id: "sr-1",
              dataCategory: "password",
              source: "message_text_request",
              quotedText: "Submit password SecretPass123 to proceed",
              riskExplanation: "Plaintext credential request",
              isDestinationVerified: false,
            },
          ],
          claims: [
            {
              id: "cl-1",
              category: "contact_info",
              claimText: "Recruiter reachable at 9876543210 or hr@fake-acme.net",
              evaluation: "Unverified",
              explanation: "Phone number 9876543210 could not be correlated with Acme",
              provenance: "message_text",
              retrievedAt: "2026-10-27T10:00:00Z",
            },
          ],
          independentVerificationRoutes: [
            {
              routeType: "corporate_contact_page",
              title: "Independent Search",
              isIndependentlyEstablished: false,
              relevanceExplanation: "Call headquarters directly instead of 9876543210",
              verifiableClaims: ["Employer Identity"],
              limitations: "Never call recruiter at 555-123-4567",
            },
          ],
          privacyRedactionsApplied: ["Phone numbers redacted"],
          disclaimer: "Legal disclaimer",
        },
      };

      // Deep copy snapshot before sanitization
      const snapshotBefore = JSON.parse(JSON.stringify(originalReport));

      const sanitized = createShareableReport(originalReport);

      // Verify original report was NOT mutated
      expect(originalReport).toEqual(snapshotBefore);

      // Verify PII is redacted in sanitized report
      const sanitizedJson = JSON.stringify(sanitized);

      // SSN redacted
      expect(sanitizedJson).not.toContain("123-45-6789");
      expect(sanitizedJson).not.toContain("987-65-4321");
      expect(sanitizedJson).toContain("[GOV ID REDACTED]");

      // Credit card redacted
      expect(sanitizedJson).not.toContain("4111-2222-3333-4444");
      expect(sanitizedJson).not.toContain("4111222233334444");
      expect(sanitizedJson).toContain("[CARD NUMBER REDACTED]");

      // Emails redacted
      expect(sanitizedJson).not.toContain("test.user@targetcorp.org");
      expect(sanitizedJson).not.toContain("hr-recruiter@victim.com");
      expect(sanitizedJson).not.toContain("john.doe@acme.com");
      expect(sanitizedJson).toContain("[EMAIL REDACTED]");

      // Phone numbers redacted
      expect(sanitizedJson).not.toContain("9876543210");
      expect(sanitizedJson).not.toContain("555-123-4567");
      expect(sanitizedJson).not.toContain("+44 7911 123456");
      expect(sanitizedJson).toContain("[PHONE REDACTED]");

      // Passwords redacted
      expect(sanitizedJson).not.toContain("SuperSecretPass123!");
      expect(sanitizedJson).not.toContain("MySecretPass#2026");
      expect(sanitizedJson).not.toContain("SecretPass123");

      // Indian PAN & Aadhaar redacted
      expect(sanitizedJson).not.toContain("ABCDE1234F");
      expect(sanitizedJson).not.toContain("2345 6789 0123");

      // Bank account & IBAN redacted
      expect(sanitizedJson).not.toContain("GB29XAAA14258324901234");
      expect(sanitizedJson).not.toContain("123456789012");
      expect(sanitizedJson).toContain("[BANK ACCOUNT REDACTED]");

      // Tokens in URLs and hash fragments stripped
      expect(sanitizedJson).not.toContain("secret_token_123");
      expect(sanitizedJson).not.toContain("jwt_fragment");
      expect(sanitizedJson).not.toContain("leak_token_123");
      expect(sanitizedJson).not.toContain("secret_jwt");

      // Verify formatReportMarkdown consumes sanitized object
      const markdown = formatReportMarkdown(originalReport);
      expect(markdown).not.toContain("123-45-6789");
      expect(markdown).not.toContain("4111-2222-3333-4444");
      expect(markdown).not.toContain("SuperSecretPass123!");
      expect(markdown).not.toContain("secret_token_123");
      expect(markdown).not.toContain("jwt_fragment");
      expect(markdown).toContain("[GOV ID REDACTED]");

      // Verify formatReportSummary consumes sanitized object
      const summary = formatReportSummary(originalReport);
      expect(summary).not.toContain("4111 2222 3333 4444");
      expect(summary).not.toContain("987-65-4321");
      expect(summary).toContain("[CARD NUMBER REDACTED]");
    });

    it("comprehensive sensitive query parameter audit: strips all candidate secret tokens while strictly preserving innocent parameters", () => {
      const complexUrl =
        "https://api.example.com/oauth/callback" +
        "?keyword=cybersecurity" +
        "&country_code=US" +
        "&zip_code=10001" +
        "&status_code=200" +
        "&page=2" +
        "&sort=asc" +
        "&token=SECRET_TOKEN_VAL" +
        "&access_token=SECRET_ACCESS_VAL" +
        "&refresh_token=SECRET_REFRESH_VAL" +
        "&id_token=SECRET_ID_VAL" +
        "&auth_token=SECRET_AUTH_VAL" +
        "&session_token=SECRET_SESS_VAL" +
        "&sessionid=SECRET_SESSID_VAL" +
        "&api_key=SECRET_APIKEY_VAL" +
        "&client_secret=SECRET_CLIENT_VAL" +
        "&private_key=SECRET_PRIVKEY_VAL" +
        "&password=SECRET_PASS_VAL" +
        "&passwd=SECRET_PASSWD_VAL" +
        "&otp=123456" +
        "&otp_code=654321" +
        "&code=OAUTH_AUTH_CODE_VAL" +
        "&state=CSRF_STATE_VAL" +
        "&jwt=eyJhbGciOiJIUzI1NiJ9.abc.xyz" +
        "&bearer=SECRET_BEARER_VAL" +
        "&signature=SECRET_SIG_VAL" +
        "&credentials=SECRET_CREDS_VAL";

      const cleaned = sanitizeUrlForSharing(complexUrl);

      // Innocent parameters MUST be preserved
      expect(cleaned).toContain("keyword=cybersecurity");
      expect(cleaned).toContain("country_code=US");
      expect(cleaned).toContain("zip_code=10001");
      expect(cleaned).toContain("status_code=200");
      expect(cleaned).toContain("page=2");
      expect(cleaned).toContain("sort=asc");

      // All sensitive secret parameters MUST be stripped
      expect(cleaned).not.toContain("SECRET_TOKEN_VAL");
      expect(cleaned).not.toContain("SECRET_ACCESS_VAL");
      expect(cleaned).not.toContain("SECRET_REFRESH_VAL");
      expect(cleaned).not.toContain("SECRET_ID_VAL");
      expect(cleaned).not.toContain("SECRET_AUTH_VAL");
      expect(cleaned).not.toContain("SECRET_SESS_VAL");
      expect(cleaned).not.toContain("SECRET_SESSID_VAL");
      expect(cleaned).not.toContain("SECRET_APIKEY_VAL");
      expect(cleaned).not.toContain("SECRET_CLIENT_VAL");
      expect(cleaned).not.toContain("SECRET_PRIVKEY_VAL");
      expect(cleaned).not.toContain("SECRET_PASS_VAL");
      expect(cleaned).not.toContain("SECRET_PASSWD_VAL");
      expect(cleaned).not.toContain("123456");
      expect(cleaned).not.toContain("654321");
      expect(cleaned).not.toContain("OAUTH_AUTH_CODE_VAL");
      expect(cleaned).not.toContain("CSRF_STATE_VAL");
      expect(cleaned).not.toContain("eyJhbGciOiJIUzI1NiJ9");
      expect(cleaned).not.toContain("SECRET_BEARER_VAL");
      expect(cleaned).not.toContain("SECRET_SIG_VAL");
      expect(cleaned).not.toContain("SECRET_CREDS_VAL");
    });

    it("handles mixed-case parameter names, duplicate sensitive keys, and authority credentials safely", () => {
      const mixedCaseUrl =
        "https://admin_user:my_secret_pass@secure.portal.org/login" +
        "?Token=UPPERCASE_SECRET" +
        "&API_KEY=KEY_SECRET_1" +
        "&api-key=KEY_SECRET_2" +
        "&Client-Secret=CLIENT_SECRET" +
        "&user_password=PASS_SECRET" +
        "&safe_context=production_login#access_token=FRAGMENT_SECRET";

      const cleaned = sanitizeUrlForSharing(mixedCaseUrl);

      // Authority credentials stripped
      expect(cleaned).not.toContain("admin_user");
      expect(cleaned).not.toContain("my_secret_pass");

      // Mixed-case keys stripped
      expect(cleaned).not.toContain("UPPERCASE_SECRET");
      expect(cleaned).not.toContain("KEY_SECRET_1");
      expect(cleaned).not.toContain("KEY_SECRET_2");
      expect(cleaned).not.toContain("CLIENT_SECRET");
      expect(cleaned).not.toContain("PASS_SECRET");
      expect(cleaned).not.toContain("FRAGMENT_SECRET");

      // Non-sensitive context preserved
      expect(cleaned).toContain("safe_context=production_login");
    });
  });

  describe("2. Job Listing Verification Accuracy", () => {
    it("does NOT issue 'Listing matched' for an official domain without specific vacancy evidence", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/",
      });

      const result = verifyJobListing({
        claimedRole: "Principal Security Architect",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(result.status).toBe("Listing not found — unverified");
      expect(result.explanation).toContain("Employer domain recognized");
      expect(result.explanation).toContain("specific vacancy not independently verified");
      expect(result.matchedListingUrl).toBeUndefined();
    });

    it("does NOT issue 'Listing matched' for a recognized ATS without specific vacancy evidence", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Airbnb",
        destinationUrl: "https://boards.greenhouse.io/airbnb",
      });

      const result = verifyJobListing({
        claimedRole: "Staff Software Engineer",
        claimedEmployer: "Airbnb",
        jobListingUrl: "https://boards.greenhouse.io/airbnb",
        companyIdentity,
        feeWarningPresent: false,
      });

      expect(result.status).toBe("Listing not found — unverified");
      expect(result.explanation).toContain("Greenhouse");
      expect(result.explanation).toContain("specific vacancy not independently verified");
    });

    it("issues 'Listing matched' when authentic infrastructure is corroborated by direct evidence", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/98765",
      });

      const result = verifyJobListing({
        claimedRole: "Site Reliability Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/98765",
        companyIdentity,
        feeWarningPresent: false,
        directEvidence: { roleMatched: true, vacancyConfirmed: true },
      });

      expect(result.status).toBe("Listing matched");
      expect(result.explanation).toContain("Site Reliability Engineer");
      expect(result.matchedListingUrl).toBe("https://careers.google.com/jobs/results/98765");
    });

    it("issues 'Listing matched' when authentic infrastructure has matching role in page title", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Microsoft",
        destinationUrl: "https://careers.microsoft.com/us/en/job/12345",
      });

      const result = verifyJobListing({
        claimedRole: "Full Stack Engineer",
        claimedEmployer: "Microsoft",
        jobListingUrl: "https://careers.microsoft.com/us/en/job/12345",
        companyIdentity,
        feeWarningPresent: false,
        observedPageTitle: "Microsoft Careers — Full Stack Engineer (Azure Core)",
      });

      expect(result.status).toBe("Listing matched");
      expect(result.explanation).toContain("Full Stack Engineer");
    });

    it("rejects generic page titles and generic role claims from falsely establishing specific vacancy", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/",
      });

      // Generic role claimed
      const genericRoleResult = verifyJobListing({
        claimedRole: "Intern",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/",
        companyIdentity,
        feeWarningPresent: false,
        observedPageTitle: "Google Careers — Jobs and Internships",
      });
      expect(genericRoleResult.status).toBe("Listing not found — unverified");

      // Specific role claimed, but page title is generic
      const genericTitleResult = verifyJobListing({
        claimedRole: "Principal Distributed Systems Engineer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/",
        companyIdentity,
        feeWarningPresent: false,
        observedPageTitle: "Google Careers — Search Jobs",
      });
      expect(genericTitleResult.status).toBe("Listing not found — unverified");
    });
  });

  describe("3. Independent Verification Route Trust", () => {
    it("never marks a user-provided unverified careers link as independently established", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        userProvidedCareersUrl: "https://google-careers-portal.fakejobs.top/apply",
      });

      expect(companyIdentity.isUserProvidedCareersUrlVerified).toBe(false);
      expect(companyIdentity.candidateCareersUrl).toBe("https://google-careers-portal.fakejobs.top/apply");
      // Official careers URL must NOT be the fake link
      expect(companyIdentity.officialCareersUrl).toBe("https://careers.google.com/");

      const routes = generateIndependentVerificationRoutes({
        companyIdentity,
        claimedRole: "Software Engineer",
      });

      // The verified official careers page is independently established
      const officialRoute = routes.find((r) => r.routeType === "official_careers_page");
      expect(officialRoute?.isIndependentlyEstablished).toBe(true);
      expect(officialRoute?.url).toBe("https://careers.google.com/");

      // The candidate careers link MUST be labeled unverified and isIndependentlyEstablished: false
      const candidateRoute = routes.find((r) => r.routeType === "user_provided_candidate");
      expect(candidateRoute).toBeDefined();
      expect(candidateRoute?.isIndependentlyEstablished).toBe(false);
      expect(candidateRoute?.title).toContain("Unverified");
      expect(candidateRoute?.relevanceExplanation).toMatch(/not been established as an official corporate portal/i);
    });

    it("guides independent search without fabricating URLs when company is unverified", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Unknown Stealth Co",
        destinationUrl: "https://stealth-company.net/contact",
      });

      const routes = generateIndependentVerificationRoutes({
        companyIdentity,
        claimedRole: "Product Lead",
      });

      const searchRoute = routes.find((r) => r.routeType === "corporate_contact_page");
      expect(searchRoute).toBeDefined();
      expect(searchRoute?.isIndependentlyEstablished).toBe(false);
      expect(searchRoute?.url).toBeUndefined();
      expect(searchRoute?.relevanceExplanation).toContain("search for the company's official corporate headquarters");
    });

    it("evaluates claims as Unverified when domain is recognized but specific role is unconfirmed", () => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: "Google",
        destinationUrl: "https://careers.google.com/jobs/results/",
      });

      const jobVerification = verifyJobListing({
        claimedRole: "Product Designer",
        claimedEmployer: "Google",
        jobListingUrl: "https://careers.google.com/jobs/results/",
        companyIdentity,
        feeWarningPresent: false,
      });

      const claims = evaluateAllClaims({
        initialClaims: [
          {
            id: "claim-role-1",
            category: "job_role",
            claimText: "Role is Senior Product Designer",
            evaluation: "Unverified",
            explanation: "",
            provenance: "message_text",
            retrievedAt: new Date().toISOString(),
          },
        ],
        companyIdentity,
        jobVerification,
        targetUrl: "https://careers.google.com/jobs/results/",
      });

      expect(claims[0].evaluation).toBe("Unverified");
      expect(claims[0].explanation).toContain("Employer domain or recruitment platform (careers.google.com) is recognized, but specific vacancy requisition could not be independently verified");
    });
  });
});
