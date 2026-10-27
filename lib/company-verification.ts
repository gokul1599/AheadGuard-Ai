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
} from "./policy";
import { validateAndNormalizeUrl } from "./url-safety";

export const RECOGNIZED_RECRUITMENT_PLATFORMS: Record<
  string,
  { name: string; rootDomain: string; isHostingJobBoard: boolean }
> = {
  "greenhouse.io": { name: "Greenhouse", rootDomain: "greenhouse.io", isHostingJobBoard: true },
  "lever.co": { name: "Lever", rootDomain: "lever.co", isHostingJobBoard: true },
  "myworkdayjobs.com": { name: "Workday Jobs", rootDomain: "myworkdayjobs.com", isHostingJobBoard: true },
  "smartrecruiters.com": { name: "SmartRecruiters", rootDomain: "smartrecruiters.com", isHostingJobBoard: true },
  "ashbyhq.com": { name: "Ashby", rootDomain: "ashbyhq.com", isHostingJobBoard: true },
  "workable.com": { name: "Workable", rootDomain: "workable.com", isHostingJobBoard: true },
  "bamboohr.com": { name: "BambooHR", rootDomain: "bamboohr.com", isHostingJobBoard: true },
  "linkedin.com": { name: "LinkedIn", rootDomain: "linkedin.com", isHostingJobBoard: true },
  "indeed.com": { name: "Indeed", rootDomain: "indeed.com", isHostingJobBoard: true },
  "wellfound.com": { name: "Wellfound (AngelList)", rootDomain: "wellfound.com", isHostingJobBoard: true },
  "internshala.com": { name: "Internshala", rootDomain: "internshala.com", isHostingJobBoard: true },
  "naukri.com": { name: "Naukri", rootDomain: "naukri.com", isHostingJobBoard: true },
};

/**
 * Checks if a given URL or hostname belongs to a recognized recruitment platform or job board.
 */
export function isRecruitmentPlatform(urlOrHostname: string): { isPlatform: boolean; platformName?: string } {
  if (!urlOrHostname) return { isPlatform: false };
  let h = urlOrHostname.toLowerCase().trim();
  try {
    if (h.includes("://")) {
      h = new URL(h).hostname.toLowerCase();
    } else if (h.includes("/")) {
      h = h.split("/")[0].toLowerCase();
    }
  } catch {
    // Keep original string if URL parse fails
  }

  for (const [domain, meta] of Object.entries(RECOGNIZED_RECRUITMENT_PLATFORMS)) {
    if (isDomainOrSubdomain(h, domain) || isSameRegistrableDomain(h, domain)) {
      return { isPlatform: true, platformName: meta.name };
    }
  }

  return { isPlatform: false };
}

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

  // If user provided a careers URL, validate it
  let validUserCareersUrl: string | undefined;
  if (userProvidedCareersUrl) {
    const safety = validateAndNormalizeUrl(userProvidedCareersUrl);
    if (safety.valid) {
      validUserCareersUrl = safety.normalizedUrl;
      evidenceSources.push({
        title: "User-Provided Official Careers URL",
        url: validUserCareersUrl,
        sourceType: "user_provided_careers_url",
        retrievedAt: now,
        snippet: "Candidate or user referenced this URL as the official careers source.",
      });
    }
  }

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
        officialCareersUrl: matchedBrand.officialCareersUrl || validUserCareersUrl,
        officialContactUrl: matchedBrand.officialContactUrl,
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
      officialCareersUrl: validUserCareersUrl,
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
      officialCareersUrl: matchedBrand?.officialCareersUrl || validUserCareersUrl,
      officialContactUrl: matchedBrand?.officialContactUrl,
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

    // Check if destination host matches official corporate domains
    const isOfficial = matchedBrand.approvedDomains.some(
      (d) => isDomainOrSubdomain(destinationHost!, d) || isSameRegistrableDomain(destinationHost!, d)
    );

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
        officialCareersUrl: matchedBrand.officialCareersUrl || validUserCareersUrl,
        officialContactUrl: matchedBrand.officialContactUrl,
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
        officialCareersUrl: matchedBrand.officialCareersUrl || validUserCareersUrl,
        officialContactUrl: matchedBrand.officialContactUrl,
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
      officialCareersUrl: matchedBrand.officialCareersUrl || validUserCareersUrl,
      officialContactUrl: matchedBrand.officialContactUrl,
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
      status: "Identity mismatch",
      explanation: claimedOrg
        ? `The sender asserts identity as "${claimedOrg}", but the destination is a shared user-hosted platform (${destinationHost}). Anyone can publish content here without corporate verification.`
        : `Destination (${destinationHost}) is a shared hosting platform without verified corporate identity.`,
      isRegisteredBrand: false,
      isOfficialCorporateDomain: false,
      isThirdPartyPlatform: false,
      officialDomains: [],
      officialCareersUrl: validUserCareersUrl,
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
    officialCareersUrl: validUserCareersUrl,
    verifiedAt: now,
    evidenceSources,
  };
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
        "The job offer demands an upfront application or training fee. This directly contradicts standard corporate recruitment practices and employment laws.",
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
    if (jobListingUrl) {
      checkedSources.push({
        title: "Provided Job Listing URL",
        url: jobListingUrl,
        sourceType: companyIdentity.status === "Official domain match" ? "official_careers_page" : "external_source",
        retrievedAt: now,
        snippet: `Application hosted on verified destination: ${companyIdentity.destinationHost}`,
      });

      return {
        claimedRole,
        claimedEmployer: claimedEmployer || companyIdentity.claimedOrganization,
        claimedLocation,
        claimedCompensation,
        recruiterContact,
        status: "Listing matched",
        explanation: `The application link directs to an authentic recruitment portal on ${companyIdentity.destinationHost}. No recruitment fees or credential harvesting were observed.`,
        matchedListingUrl: jobListingUrl,
        checkedSources,
        verifiedAt: now,
        limitations:
          "Listing link verified on authentic recruitment infrastructure. Confirm specific recruiter identity if contacted through unofficial email addresses.",
      };
    }
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
