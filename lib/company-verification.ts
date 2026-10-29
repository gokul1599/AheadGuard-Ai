import {
  ClaimSourceReference,
  CompanyIdentityVerification,
  JobVerificationResult,
} from "./types";
import {
  BRAND_DOMAIN_REGISTRY,
  getRegistrableDomain,
  isDomainOrSubdomain,
  isSameRegistrableDomain,
  matchesBrandAlias,
  isUserHostedPlatform,
  RECOGNIZED_RECRUITMENT_PLATFORMS,
  isRecruitmentPlatform,
} from "./policy";
import { validateAndNormalizeUrl } from "./url-safety";

export { RECOGNIZED_RECRUITMENT_PLATFORMS, isRecruitmentPlatform };

/**
 * Finds a matching canonical brand entry from the registry given a claimed name.
 */
export function findBrandInRegistry(claimedName: string) {
  if (!claimedName || typeof claimedName !== "string") return undefined;
  const nameClean = claimedName.toLowerCase().trim();

  for (const [key, entry] of Object.entries(BRAND_DOMAIN_REGISTRY)) {
    if (
      entry.canonicalName.toLowerCase() === nameClean ||
      key === nameClean ||
      entry.aliases.some((alias) => alias === nameClean || matchesBrandAlias(nameClean, alias))
    ) {
      return entry;
    }
  }

  return undefined;
}

/**
 * Verifies claimed company identity against the destination URL and independent registry.
 */
export function verifyCompanyIdentity(params: {
  claimedOrg?: string;
  destinationUrl?: string;
  userProvidedCareersUrl?: string;
}): CompanyIdentityVerification {
  const { claimedOrg, destinationUrl, userProvidedCareersUrl } = params;
  const now = new Date().toISOString();

  let destinationHost: string | undefined;
  let registrableDomain: string | undefined;

  if (destinationUrl) {
    try {
      const parsed = new URL(destinationUrl);
      destinationHost = parsed.hostname.toLowerCase();
      registrableDomain = getRegistrableDomain(destinationHost);
    } catch {
      // Invalid destination URL
    }
  }

  // 1. Check if claimed organization is recognized in verified brand registry
  const matchedBrand = claimedOrg ? findBrandInRegistry(claimedOrg) : undefined;
  const platformCheck = destinationHost ? isRecruitmentPlatform(destinationHost) : { isPlatform: false };

  const evidenceSources: ClaimSourceReference[] = [];

  // If user provided a careers URL, validate it and check if it belongs to approved corporate domains
  let validUserCareersUrl: string | undefined;
  let isUserCareersVerified = false;
  if (userProvidedCareersUrl) {
    const safety = validateAndNormalizeUrl(userProvidedCareersUrl);
    if (safety.valid) {
      validUserCareersUrl = safety.normalizedUrl;
      try {
        const userHost = new URL(validUserCareersUrl).hostname.toLowerCase();
        if (
          matchedBrand &&
          matchedBrand.approvedDomains.some(
            (d) => isDomainOrSubdomain(userHost, d) || isSameRegistrableDomain(userHost, d)
          )
        ) {
          isUserCareersVerified = true;
        }
      } catch {
        isUserCareersVerified = false;
      }

      if (isUserCareersVerified) {
        evidenceSources.push({
          title: "Verified User-Provided Official Careers URL",
          url: validUserCareersUrl,
          sourceType: "official_careers_page",
          retrievedAt: now,
          snippet: `Candidate careers URL was verified against approved corporate domains for ${matchedBrand?.canonicalName}.`,
        });
      } else {
        evidenceSources.push({
          title: "User-Provided Candidate Careers Link (Unverified)",
          url: validUserCareersUrl,
          sourceType: "user_provided_careers_url",
          retrievedAt: now,
          snippet: "Candidate careers URL supplied by user has not been independently verified against official corporate domains.",
        });
      }
    }
  }

  // Official careers URL MUST only be from brand registry or verified user-supplied corporate domain
  const verifiedOfficialCareersUrl =
    (isUserCareersVerified ? validUserCareersUrl : undefined) || matchedBrand?.officialCareersUrl;

  // Scenario A: No destination URL provided (message analysis only)
  if (!destinationHost) {
    if (matchedBrand) {
      evidenceSources.push({
        title: `${matchedBrand.canonicalName} Verified Brand Registry Record`,
        url: `https://${matchedBrand.approvedDomains[0]}`,
        sourceType: "brand_registry",
        retrievedAt: now,
        snippet: `Verified corporate domains: ${matchedBrand.approvedDomains.join(", ")}`,
      });

      return {
        claimedOrganization: matchedBrand.canonicalName,
        status: "Unverified identity",
        explanation: `Claimed organization "${matchedBrand.canonicalName}" is a known high-profile organization, but no destination link was supplied to verify the message origin.`,
        isRegisteredBrand: true,
        isOfficialCorporateDomain: false,
        isThirdPartyPlatform: false,
        officialDomains: matchedBrand.approvedDomains,
        officialCareersUrl: verifiedOfficialCareersUrl,
        officialContactUrl: matchedBrand.officialContactUrl,
        candidateCareersUrl: validUserCareersUrl,
        isUserProvidedCareersUrlVerified: isUserCareersVerified,
        verifiedAt: now,
        evidenceSources,
      };
    }

    return {
      claimedOrganization: claimedOrg,
      status: "Unverified identity",
      explanation: claimedOrg
        ? `Organization "${claimedOrg}" is not registered in AheadGuard's high-assurance brand directory and no destination link was provided.`
        : "No organization identity or destination link was specified.",
      isRegisteredBrand: false,
      isOfficialCorporateDomain: false,
      isThirdPartyPlatform: false,
      officialDomains: [],
      officialCareersUrl: verifiedOfficialCareersUrl,
      candidateCareersUrl: validUserCareersUrl,
      isUserProvidedCareersUrlVerified: isUserCareersVerified,
      verifiedAt: now,
      evidenceSources,
    };
  }

  // Scenario B: Destination URL is on a recognized Third-Party Recruitment Platform (e.g. Greenhouse, Workday, LinkedIn)
  if (platformCheck.isPlatform && platformCheck.platformName) {
    evidenceSources.push({
      title: `${platformCheck.platformName} Recruitment Platform`,
      url: `https://${destinationHost}`,
      sourceType: "external_source",
      retrievedAt: now,
      snippet: `Destination is hosted on ${platformCheck.platformName}, an established enterprise applicant tracking system.`,
    });

    return {
      claimedOrganization: matchedBrand?.canonicalName || claimedOrg,
      destinationHost,
      registrableDomain,
      status: "Third-party platform",
      explanation: `The destination is hosted on ${platformCheck.platformName}, an established recruitment and job board platform. While legitimate companies routinely host application portals on ${platformCheck.platformName}, ensure the specific company sub-account matches the employer.`,
      isRegisteredBrand: Boolean(matchedBrand),
      isOfficialCorporateDomain: false,
      isThirdPartyPlatform: true,
      platformName: platformCheck.platformName,
      officialDomains: matchedBrand ? matchedBrand.approvedDomains : [],
      officialCareersUrl: verifiedOfficialCareersUrl,
      officialContactUrl: matchedBrand?.officialContactUrl,
      candidateCareersUrl: validUserCareersUrl,
      isUserProvidedCareersUrlVerified: isUserCareersVerified,
      verifiedAt: now,
      evidenceSources,
    };
  }

  // Scenario C: Claimed organization is in the verified Brand Registry
  if (matchedBrand) {
    evidenceSources.push({
      title: `${matchedBrand.canonicalName} Brand Registry Record`,
      url: `https://${matchedBrand.approvedDomains[0]}`,
      sourceType: "brand_registry",
      retrievedAt: now,
      snippet: `Approved corporate domains: ${matchedBrand.approvedDomains.join(", ")}`,
    });

    // Check if destination host matches official corporate domains or official careers portal
    let isOfficial = matchedBrand.approvedDomains.some(
      (d) => isDomainOrSubdomain(destinationHost!, d) || isSameRegistrableDomain(destinationHost!, d)
    );

    if (!isOfficial && matchedBrand.officialCareersUrl) {
      try {
        const cu = new URL(matchedBrand.officialCareersUrl);
        if (isDomainOrSubdomain(destinationHost!, cu.hostname) || isSameRegistrableDomain(destinationHost!, cu.hostname)) {
          isOfficial = true;
        }
      } catch {}
    }

    if (isOfficial) {
      return {
        claimedOrganization: matchedBrand.canonicalName,
        destinationHost,
        registrableDomain,
        status: "Official domain match",
        explanation: `Destination (${destinationHost}) directly matches the verified official corporate domain for ${matchedBrand.canonicalName}.`,
        isRegisteredBrand: true,
        isOfficialCorporateDomain: true,
        isThirdPartyPlatform: false,
        officialDomains: matchedBrand.approvedDomains,
        officialCareersUrl: verifiedOfficialCareersUrl,
        officialContactUrl: matchedBrand.officialContactUrl,
        candidateCareersUrl: validUserCareersUrl,
        isUserProvidedCareersUrlVerified: isUserCareersVerified,
        verifiedAt: now,
        evidenceSources,
      };
    }

    // Check affiliated authentication domains
    const isAffiliated = (matchedBrand.affiliatedAuthDomains || []).some(
      (d) => isDomainOrSubdomain(destinationHost!, d) || isSameRegistrableDomain(destinationHost!, d)
    );

    if (isAffiliated) {
      return {
        claimedOrganization: matchedBrand.canonicalName,
        destinationHost,
        registrableDomain,
        status: "Affiliated domain observed",
        explanation: `Destination (${destinationHost}) is a recognized affiliated authentication/service domain for ${matchedBrand.canonicalName}.`,
        isRegisteredBrand: true,
        isOfficialCorporateDomain: false,
        isThirdPartyPlatform: false,
        officialDomains: matchedBrand.approvedDomains,
        officialCareersUrl: verifiedOfficialCareersUrl,
        officialContactUrl: matchedBrand.officialContactUrl,
        candidateCareersUrl: validUserCareersUrl,
        isUserProvidedCareersUrlVerified: isUserCareersVerified,
        verifiedAt: now,
        evidenceSources,
      };
    }

    // Host does NOT match official domains -> IDENTITY MISMATCH
    const isShared = isUserHostedPlatform(destinationHost);
    return {
      claimedOrganization: matchedBrand.canonicalName,
      destinationHost,
      registrableDomain,
      status: "Identity mismatch",
      explanation: isShared
        ? `The message claims to represent "${matchedBrand.canonicalName}", but the destination is hosted on a public user-generated hosting service (${destinationHost}) rather than the official domain (${matchedBrand.approvedDomains[0]}).`
        : `Identity mismatch: The message claims to represent "${matchedBrand.canonicalName}", but the link directs to "${destinationHost}", which is NOT an official domain of ${matchedBrand.canonicalName} (${matchedBrand.approvedDomains.join(", ")}).`,
      isRegisteredBrand: true,
      isOfficialCorporateDomain: false,
      isThirdPartyPlatform: false,
      officialDomains: matchedBrand.approvedDomains,
      officialCareersUrl: verifiedOfficialCareersUrl,
      officialContactUrl: matchedBrand.officialContactUrl,
      candidateCareersUrl: validUserCareersUrl,
      isUserProvidedCareersUrlVerified: isUserCareersVerified,
      verifiedAt: now,
      evidenceSources,
    };
  }

  // Scenario D: Organization is not in the Brand Registry
  // Check if destination is a user-hosted platform (e.g. github.io, vercel.app, etc.)
  if (isUserHostedPlatform(destinationHost)) {
    return {
      claimedOrganization: claimedOrg,
      destinationHost,
      registrableDomain,
      status: "Unverified identity",
      explanation: claimedOrg
        ? `The sender asserts identity as "${claimedOrg}", but the destination is hosted on a public user-generated hosting service (${destinationHost}). Content published here is not authenticated by an official enterprise domain.`
        : `Destination (${destinationHost}) is a shared hosting platform without verified corporate identity.`,
      isRegisteredBrand: false,
      isOfficialCorporateDomain: false,
      isThirdPartyPlatform: false,
      officialDomains: [],
      officialCareersUrl: verifiedOfficialCareersUrl,
      candidateCareersUrl: validUserCareersUrl,
      isUserProvidedCareersUrlVerified: isUserCareersVerified,
      verifiedAt: now,
      evidenceSources,
    };
  }

  // General unverified company
  return {
    claimedOrganization: claimedOrg,
    destinationHost,
    registrableDomain,
    status: "Unverified identity",
    explanation: claimedOrg
      ? `The organization "${claimedOrg}" is not present in AheadGuard's verified brand registry. The destination domain "${destinationHost}" could not be independently authenticated.`
      : `The destination domain "${destinationHost}" could not be correlated with a verified corporate identity.`,
    isRegisteredBrand: false,
    isOfficialCorporateDomain: false,
    isThirdPartyPlatform: false,
    officialDomains: [],
    officialCareersUrl: verifiedOfficialCareersUrl,
    candidateCareersUrl: validUserCareersUrl,
    isUserProvidedCareersUrlVerified: isUserCareersVerified,
    verifiedAt: now,
    evidenceSources,
  };
}

/**
 * Helper to test whether substantive words in claimedRole appear in candidate text.
 * Requires specific, attributable role tokens on word boundaries.
 * Generic role terms ("job", "intern", "careers") or generic page titles alone
 * cannot falsely establish that a specific vacancy exists.
 */
export function matchesRoleText(claimedRole?: string, candidateText?: string): boolean {
  if (!claimedRole || !candidateText) return false;
  const roleClean = claimedRole.trim();
  const textClean = candidateText.trim();
  if (roleClean.length < 3 || textClean.length === 0) return false;

  // Generic recruitment terms that cannot alone establish a specific role vacancy
  const genericRecruitmentTerms = new Set([
    "and",
    "or",
    "the",
    "a",
    "an",
    "for",
    "at",
    "in",
    "to",
    "of",
    "with",
    "is",
    "intern",
    "interns",
    "internship",
    "internships",
    "job",
    "jobs",
    "role",
    "roles",
    "position",
    "positions",
    "opening",
    "openings",
    "opportunity",
    "opportunities",
    "career",
    "careers",
    "employment",
    "work",
    "apply",
    "application",
    "hiring",
    "recruitment",
    "portal",
  ]);

  // Valid two-letter domain/role acronyms that must not be discarded
  const validTwoLetterTokens = new Set(["qa", "ui", "ux", "ai", "ml", "hr", "it", "qc", "pm"]);

  const tokens = roleClean
    .split(/[\s\-_/,\.:;]+/)
    .map((t) => t.trim().toLowerCase())
    .filter((t) => (t.length > 2 || validTwoLetterTokens.has(t)) && !genericRecruitmentTerms.has(t));

  // If claimedRole has NO specific substantive role keywords (e.g. user just said "Job" or "Internship"),
  // generic page titles or site headers must NOT falsely match it as a verified specific vacancy.
  if (tokens.length === 0) {
    return false;
  }

  // All substantive tokens must appear as distinct whole words in candidate text
  return tokens.every((token) => {
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const wordPattern = new RegExp(`(?:^|[^a-zA-Z0-9])${escaped}(?:$|[^a-zA-Z0-9])`, "i");
    return wordPattern.test(textClean);
  });
}

/**
 * Evaluates the legitimacy of a job/internship offer by cross-referencing
 * the claimed role and employer against verified careers sources and observed facts.
 */
export function verifyJobListing(params: {
  claimedRole?: string;
  claimedEmployer?: string;
  claimedLocation?: string;
  claimedCompensation?: string;
  recruiterContact?: string;
  jobListingUrl?: string;
  companyIdentity: CompanyIdentityVerification;
  feeWarningPresent: boolean;
  directEvidence?: {
    roleMatched?: boolean;
    vacancyConfirmed?: boolean;
    evidenceSnippet?: string;
  };
  observedPageTitle?: string;
  observedPageSnippet?: string;
}): JobVerificationResult {
  const {
    claimedRole,
    claimedEmployer,
    claimedLocation,
    claimedCompensation,
    recruiterContact,
    jobListingUrl,
    companyIdentity,
    feeWarningPresent,
    directEvidence,
    observedPageTitle,
    observedPageSnippet,
  } = params;

  const now = new Date().toISOString();
  const checkedSources: ClaimSourceReference[] = [...companyIdentity.evidenceSources];

  // 1. Direct contradiction: Upfront recruitment fee requested
  if (feeWarningPresent) {
    return {
      claimedRole,
      claimedEmployer: claimedEmployer || companyIdentity.claimedOrganization,
      claimedLocation,
      claimedCompensation,
      recruiterContact,
      status: "Listing contradicted",
      explanation:
        "The job offer demands an upfront application or training fee. This directly contradicts standard corporate recruitment practices where legitimate employers do not charge applicants fees for hiring or training.",
      checkedSources,
      verifiedAt: now,
      limitations:
        "Direct contradiction: Legitimate employers do not require job applicants or interns to pay fees for employment.",
    };
  }

  // 2. Direct contradiction: Identity mismatch on destination
  if (companyIdentity.status === "Identity mismatch") {
    return {
      claimedRole,
      claimedEmployer: claimedEmployer || companyIdentity.claimedOrganization,
      claimedLocation,
      claimedCompensation,
      recruiterContact,
      status: "Listing contradicted",
      explanation: `The job offer claims to be from ${companyIdentity.claimedOrganization || "the organization"}, but the application link directs to an unverified or mismatched domain (${companyIdentity.destinationHost}).`,
      checkedSources,
      verifiedAt: now,
      limitations: "Direct contradiction: The application destination is not affiliated with the claimed employer.",
    };
  }

  // 3. Official domain match or recognized third-party recruitment platform
  if (companyIdentity.status === "Official domain match" || companyIdentity.status === "Third-party platform") {
    // Check for direct evidence or crawled page title/snippet matching the specific role
    const hasRoleDirectEvidence = Boolean(directEvidence?.roleMatched || directEvidence?.vacancyConfirmed);
    const hasRolePageMatch = Boolean(
      matchesRoleText(claimedRole, observedPageTitle) ||
      matchesRoleText(claimedRole, observedPageSnippet) ||
      matchesRoleText(claimedRole, directEvidence?.evidenceSnippet)
    );
    const isVacancyConfirmed = hasRoleDirectEvidence || hasRolePageMatch;

    if (isVacancyConfirmed) {
      if (jobListingUrl) {
        checkedSources.push({
          title: "Verified Vacancy Listing URL",
          url: jobListingUrl,
          sourceType: companyIdentity.status === "Official domain match" ? "official_careers_page" : "external_source",
          retrievedAt: now,
          snippet: `Application hosted on authentic destination: ${companyIdentity.destinationHost}`,
        });
      }

      const platformLabel =
        companyIdentity.status === "Official domain match"
          ? `authentic corporate recruitment portal on ${companyIdentity.destinationHost}`
          : `${companyIdentity.platformName || "recruitment platform"} (${companyIdentity.destinationHost})`;

      return {
        claimedRole,
        claimedEmployer: claimedEmployer || companyIdentity.claimedOrganization,
        claimedLocation,
        claimedCompensation,
        recruiterContact,
        status: "Listing matched",
        explanation: `The specific vacancy "${claimedRole || "unspecified"}" was verified on ${platformLabel}. No recruitment fees or credential harvesting were observed.`,
        matchedListingUrl: jobListingUrl || companyIdentity.officialCareersUrl,
        checkedSources,
        verifiedAt: now,
        limitations:
          "Listing link and vacancy confirmed on authentic recruitment infrastructure. Confirm specific recruiter identity if contacted through unofficial email addresses.",
      };
    }

    // Employer domain or ATS recognized, BUT specific vacancy is not verified
    if (jobListingUrl) {
      checkedSources.push({
        title: "Observed Application Destination",
        url: jobListingUrl,
        sourceType: companyIdentity.status === "Official domain match" ? "official_careers_page" : "external_source",
        retrievedAt: now,
        snippet: `Destination verified on ${companyIdentity.destinationHost}, but specific vacancy was not verified in page metadata.`,
      });
    }

    const infrastructureLabel =
      companyIdentity.isThirdPartyPlatform && companyIdentity.platformName
        ? `Recruitment platform recognized (${companyIdentity.platformName} at ${companyIdentity.destinationHost})`
        : `Employer domain recognized (${companyIdentity.destinationHost})`;

    return {
      claimedRole,
      claimedEmployer: claimedEmployer || companyIdentity.claimedOrganization,
      claimedLocation,
      claimedCompensation,
      recruiterContact,
      status: "Listing not found — unverified",
      explanation: `${infrastructureLabel}; specific vacancy not independently verified. Destination belongs to authentic recruitment infrastructure, but AheadGuard could not independently verify that the specific vacancy${claimedRole ? ` "${claimedRole}"` : ""} exists without an official requisition lookup.`,
      checkedSources,
      verifiedAt: now,
      limitations:
        "Authentic recruitment infrastructure confirmed, but specific vacancy requisition not verified. Requisition IDs and job openings should be verified directly through official portal search.",
    };
  }

  // 4. Default: Listing not found — unverified
  return {
    claimedRole,
    claimedEmployer: claimedEmployer || companyIdentity.claimedOrganization,
    claimedLocation,
    claimedCompensation,
    recruiterContact,
    status: "Listing not found — unverified",
    explanation:
      "The role could not be cross-referenced against an independently verified official careers listing. This is an unverified listing, not a guarantee of fraud.",
    checkedSources,
    verifiedAt: now,
    limitations:
      "Absence of an indexed public post does not definitively prove fraud (roles may be private, newly opened, or recruiter-direct). However, candidates should independently verify before disclosing personal documents.",
  };
}
