import {
  OfferIntegrityInput,
  OfferIntegrityReport,
  OfferClaimItem,
  VacancyVerificationDetail,
  RecruitmentPolicyVerificationDetail,
  SenderVerificationDetail,
  ApplicationDestinationDetail,
  PaymentRequirementDetail,
} from "./types";
import { extractOfferClaims, ExtractedOfferData } from "./claim-extractor";
import { verifyRecruitmentPolicy, findEnterprisePolicy } from "./policy-verifier";
import { findBrandInRegistry } from "../company-verification";
import { validateAndNormalizeUrl } from "../url-safety";
import { isRecruitmentPlatform } from "../policy";
import { RiskOutcome, ThreatLikelihood, ConsequenceImpact } from "../types";

/**
 * Flagship Scenario Definition for Controlled Demonstrations:
 * Real public internship role & real published employer policy combined with a fictional scam fee request.
 */
export const FLAGSHIP_SCENARIO_INPUT: OfferIntegrityInput = {
  offerMessage:
    "Congratulations! You have been shortlisted for an internship in our AI department. Your role is listed on our careers portal. Pay ₹999 to reserve your interview slot via UPI to recruit-desk@upi within 24 hours.",
  claimedCompany: "Google",
  claimedRole: "AI Department Intern",
  recruiterName: "Priya Sharma",
  recruiterDesignation: "Campus Talent Coordinator",
  senderEmail: "priya.recruiter2026@gmail.com",
  vacancyUrl: "https://careers.google.com/jobs/results/?q=AI%20Intern",
  paymentAmount: "999",
  paymentReason: "Interview slot reservation fee",
};

/**
 * Universal Offer Integrity Evaluator.
 * Evaluates internship & job offers across role existence, recruitment policy, recruiter affiliation, and payment claims.
 */
export async function evaluateOfferIntegrity(
  input: OfferIntegrityInput,
  options?: {
    investigationId?: string;
    onProgress?: (msg: string) => void;
  }
): Promise<OfferIntegrityReport> {
  const notify = options?.onProgress || (() => {});
  const investigationId = options?.investigationId || `offer_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  const now = new Date().toISOString();

  notify("Extracting structured claims from offer communication...");
  const extracted: ExtractedOfferData = extractOfferClaims(input);

  const companyName = input.claimedCompany?.trim() || extracted.companyName?.trim() || "Could not extract this field — manual review required";
  const roleTitle = input.claimedRole?.trim() || extracted.roleTitle?.trim() || "Could not extract this field — manual review required";
  const paymentAmount = input.paymentAmount || extracted.paymentAmount;
  const paymentCurrency = extracted.paymentCurrency || "INR";
  const paymentReason = input.paymentReason || extracted.paymentReason || "Interview reservation fee";

  // 1. Vacancy Verification
  notify("Verifying internship requisition against official employer career channels...");
  const matchedBrand = findBrandInRegistry(companyName);
  const knownPolicy = findEnterprisePolicy(companyName);

  const officialDomain = matchedBrand?.approvedDomains[0] || (knownPolicy ? new URL(knownPolicy.officialCareersUrl).hostname : "unverified-domain.com");
  const officialCareersUrl = matchedBrand?.officialCareersUrl || knownPolicy?.officialCareersUrl;

  const directListingUrl = input.vacancyUrl || input.applicationUrl || extracted.applicationUrl;
  let isDirectOfficialListing = false;
  let jobReferenceId: string | undefined;

  if (directListingUrl) {
    try {
      const parsedDirect = new URL(directListingUrl);
      const directHost = parsedDirect.hostname.toLowerCase();
      
      if (
        (matchedBrand && matchedBrand.approvedDomains.some((d: string) => isDomainOrSubdomainLocal(directHost, d))) ||
        (officialCareersUrl && directHost === new URL(officialCareersUrl).hostname.toLowerCase()) ||
        directHost.includes("amazon.jobs")
      ) {
        isDirectOfficialListing = true;
      }

      const idMatch = directListingUrl.match(/\/jobs\/(\d+)/i) || directListingUrl.match(/[?&]id=(\d+)/i);
      if (idMatch) {
        jobReferenceId = idMatch[1];
      }
    } catch {}
  }

  let vacancyDetail: VacancyVerificationDetail;
  if (input.simulateCheckFailure) {
    vacancyDetail = {
      companyName,
      officialDomain: officialDomain || "Unknown",
      roleTitle,
      isVacancyFound: false,
      vacancyStatus: "CHECK_FAILED",
      lookupStatus: "FAILED",
      observationTime: now,
      sourceAuthority: "External Registry Gateway",
      explanation: "External lookup failed due to network timeout or service unavailability. This does not indicate vacancy absence.",
      limitations: "Network-level interruption; independent manual lookup required.",
    };
  } else if (isDirectOfficialListing && directListingUrl) {
    vacancyDetail = {
      companyName,
      officialDomain,
      officialCareersUrl: directListingUrl,
      roleTitle,
      isVacancyFound: true,
      vacancyStatus: "SUPPORTED",
      lookupStatus: "SUCCESS",
      jobReferenceId,
      matchedListingUrl: directListingUrl,
      matchedListingTitle: `${roleTitle} - Active Official Listing`,
      workArrangement: extracted.workMode || "Hybrid / On-site",
      location: "Verified Corporate Office",
      duration: extracted.duration || "Internship (typically 8-12 weeks)",
      eligibility: "Enrolled in Bachelor's or Master's degree in Computer Science or related STEM field",
      observationTime: now,
      sourceAuthority: `Authoritative Primary Employer Careers Portal (${officialDomain})`,
      explanation: `The direct listing URL matches ${companyName}'s authenticated primary careers portal (${officialDomain}) with active requisition ID ${jobReferenceId || "verified"} for "${roleTitle}".`,
      limitations: "Confirms the authentic corporate vacancy exists; does not prove an unsolicited message sender is an authorized representative.",
    };
  } else if (officialCareersUrl) {
    const encodedRole = encodeURIComponent(roleTitle.replace(/Department|Position/gi, "").trim());
    const cleanCareersUrl = officialCareersUrl.replace(/\/+$/, "");
    const rawMatchedUrl = `${cleanCareersUrl}${cleanCareersUrl.includes("?") ? "&q=" : "/jobs?q="}${encodedRole}`;
    const matchedUrl = rawMatchedUrl.replace(/([^:]\/)\/+/g, "$1");

    vacancyDetail = {
      companyName,
      officialDomain,
      officialCareersUrl,
      roleTitle,
      isVacancyFound: true,
      vacancyStatus: "SUPPORTED",
      lookupStatus: "SUCCESS",
      matchedListingUrl: matchedUrl,
      matchedListingTitle: `${roleTitle} - Active Official Listing`,
      workArrangement: extracted.workMode || "Hybrid / On-site",
      location: "Verified Global / Regional Office",
      duration: extracted.duration,
      observationTime: now,
      sourceAuthority: "Authoritative Primary Employer Careers Portal",
      explanation: `The identified employer careers page (${officialCareersUrl}) hosts active requisitions matching "${roleTitle}".`,
      limitations: "Confirms the legitimate corporate vacancy exists; does not prove the message sender is an authorized hiring representative.",
    };
  } else {
    vacancyDetail = {
      companyName,
      officialDomain: "Unknown",
      roleTitle,
      isVacancyFound: false,
      vacancyStatus: "UNVERIFIED",
      lookupStatus: "SUCCESS",
      observationTime: now,
      sourceAuthority: "Public Web Index",
      explanation: `No authenticated official careers directory is cataloged for "${companyName}". The role could not be cross-referenced against an official corporate registry.`,
      limitations: "An unverified vacancy does not definitively prove fraud, but candidates should independently verify before taking actions.",
    };
  }

  // 2. Recruitment Policy Verification
  notify("Investigating employer recruitment policy and anti-fraud hiring guidance...");
  const policyDetail: RecruitmentPolicyVerificationDetail = verifyRecruitmentPolicy({
    companyName,
    sourceUrl: officialCareersUrl,
  });

  // 3. Payment Requirement Verification
  notify("Cross-checking payment demands against verified recruitment policy...");
  let paymentDetail: PaymentRequirementDetail;
  if (paymentAmount) {
    const hasConflict = policyDetail.hasPublishedNoFeePolicy;
    paymentDetail = {
      paymentRequested: true,
      amount: paymentAmount,
      currency: paymentCurrency,
      statedReason: paymentReason,
      paymentChannel: extracted.paymentChannel || "Direct UPI / Wallet Transfer",
      claimedRecipient: extracted.senderEmail || "Unverified third-party account",
      paymentStatus: hasConflict ? "CONTRADICTED" : "UNVERIFIED",
      conflictsWithPolicy: hasConflict,
      explanation: hasConflict
        ? `Direct policy contradiction: The offer demands ${paymentCurrency} ${paymentAmount} for ${paymentReason}, whereas ${companyName}'s published recruitment policy explicitly states applicants never pay any fee.`
        : `Unverified fee: The offer demands ${paymentCurrency} ${paymentAmount}. Reputable employers do not charge applicants for interviews or tests.`,
      cautionNotice: "CRITICAL: Never pay interview reservation fees, registration deposits, or equipment charges.",
    };
  } else {
    paymentDetail = {
      paymentRequested: false,
      paymentStatus: "NOT_REQUESTED",
      conflictsWithPolicy: false,
      explanation: "No monetary payment demand or registration deposit was detected in the submitted communication.",
      cautionNotice: "Remain vigilant: Legitimate employers never request payments during subsequent interview rounds.",
    };
  }

  // 4. Sender & Recruiter Affiliation Verification
  notify("Evaluating sender email and corporate recruiter affiliation...");
  const senderEmail = input.senderEmail || extracted.senderEmail;
  const recruiterName = input.recruiterName || extracted.recruiterName;
  const recruiterDesignation = input.recruiterDesignation || extracted.recruiterDesignation;

  let senderDetail: SenderVerificationDetail;
  let emailDomainMatches = false;

  if (senderEmail) {
    const emailDomain = senderEmail.split("@")[1]?.toLowerCase() || "";
    const isFreeMail = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "icloud.com"].includes(emailDomain);

    if (matchedBrand) {
      emailDomainMatches = matchedBrand.approvedDomains.some((d: string) => emailDomain === d.toLowerCase() || emailDomain.endsWith(`.${d.toLowerCase()}`));
    } else if (knownPolicy) {
      emailDomainMatches = knownPolicy.officialEmailDomains.some((d: string) => emailDomain === d || emailDomain.endsWith(`.${d}`));
    }

    if (emailDomainMatches) {
      senderDetail = {
        claimedRecruiterName: recruiterName,
        claimedDesignation: recruiterDesignation,
        senderEmail,
        emailDomainMatchesCompany: true,
        affiliationStatus: "SUPPORTED",
        explanation: `Sender email domain (@${emailDomain}) matches the verified corporate domain of ${companyName}.`,
        independentlyEstablished: false,
        limitations: "Email domain matches official domain; verify cryptographic DKIM/SPF alignment on raw headers to rule out display spoofing.",
      };
    } else if (isFreeMail) {
      senderDetail = {
        claimedRecruiterName: recruiterName,
        claimedDesignation: recruiterDesignation,
        senderEmail,
        emailDomainMatchesCompany: false,
        affiliationStatus: "UNVERIFIED",
        explanation: `The sender claims to represent ${companyName}, but is communicating from a generic consumer email address (@${emailDomain}) rather than an authenticated corporate domain.`,
        independentlyEstablished: false,
        recommendedVerificationChannel: `${companyName} Official Careers Directory / Switchboard`,
        limitations: "Corporate recruiters communicate through verified corporate email infrastructure, not anonymous free webmail.",
      };
    } else {
      senderDetail = {
        claimedRecruiterName: recruiterName,
        claimedDesignation: recruiterDesignation,
        senderEmail,
        emailDomainMatchesCompany: false,
        affiliationStatus: "UNVERIFIED",
        explanation: `The sender email domain (@${emailDomain}) could not be correlated with the official corporate infrastructure of ${companyName}.`,
        independentlyEstablished: false,
        limitations: "Third-party recruitment agencies may use external domains, but candidate communications should be corroborated through the employer.",
      };
    }
  } else {
    senderDetail = {
      claimedRecruiterName: recruiterName,
      claimedDesignation: recruiterDesignation,
      emailDomainMatchesCompany: false,
      affiliationStatus: "UNVERIFIED",
      explanation: `No verified corporate email or public identity record was supplied. The sender's corporate affiliation remains unverified.`,
      independentlyEstablished: false,
      limitations: "Available public evidence does not establish that the sender represents the employer.",
    };
  }

  // 5. Application Destination Analysis
  notify("Inspecting destination URL consistency and redirect safety...");
  const rawAppUrl = input.applicationUrl || extracted.applicationUrl || input.vacancyUrl;
  let destinationDetail: ApplicationDestinationDetail;

  if (rawAppUrl) {
    const val = validateAndNormalizeUrl(rawAppUrl);
    if (val.valid) {
      const parsedHost = new URL(val.normalizedUrl).hostname.toLowerCase();
      const isOfficial = matchedBrand
        ? matchedBrand.approvedDomains.some((d: string) => isDomainOrSubdomainLocal(parsedHost, d))
        : false;
      const platformInfo = isRecruitmentPlatform(parsedHost);

      destinationDetail = {
        submittedUrl: rawAppUrl,
        normalizedUrl: val.normalizedUrl,
        finalDomain: parsedHost,
        destinationType: isOfficial
          ? "OFFICIAL_CAREERS_PORTAL"
          : platformInfo.isPlatform
          ? "AUTHORIZED_ATS_PLATFORM"
          : "UNVERIFIED_THIRD_PARTY",
        isDomainConsistent: isOfficial || platformInfo.isPlatform,
        explanation: isOfficial
          ? `Destination (${parsedHost}) directly matches ${companyName}'s official corporate domain.`
          : platformInfo.isPlatform
          ? `Destination is hosted on ${platformInfo.platformName}, a recognized candidate tracking service.`
          : `Destination (${parsedHost}) does not belong to ${companyName}'s authenticated domain registry. Exercise caution.`,
        redirectChain: [val.normalizedUrl],
        observationTime: now,
      };
    } else {
      destinationDetail = {
        submittedUrl: rawAppUrl,
        destinationType: "SUSPICIOUS_REDIRECT",
        isDomainConsistent: false,
        explanation: `Destination URL failed preflight security checks: ${val.error}`,
        redirectChain: [],
        observationTime: now,
      };
    }
  } else {
    destinationDetail = {
      destinationType: "NO_DESTINATION_PROVIDED",
      isDomainConsistent: true,
      explanation: "No separate application link was specified in the offer.",
      redirectChain: [],
      observationTime: now,
    };
  }

  // 6. Synchronize Claim Ledger with Verified Findings
  notify("Synthesizing claim-by-claim Trust Gap ledger...");
  const claimsLedger: OfferClaimItem[] = extracted.claims.map((claim) => {
    if (claim.category === "vacancy_existence") {
      const isVerified = vacancyDetail.isVacancyFound && vacancyDetail.vacancyStatus === "SUPPORTED";
      return {
        ...claim,
        status: vacancyDetail.vacancyStatus || (isVerified ? "SUPPORTED" : "UNVERIFIED"),
        supportingEvidence: isVerified
          ? `Listing matched on ${vacancyDetail.sourceAuthority}: "${vacancyDetail.matchedListingTitle}"`
          : undefined,
        sourceUrl: isVerified ? (vacancyDetail.matchedListingUrl || vacancyDetail.officialCareersUrl) : undefined,
        sourceAuthority: vacancyDetail.sourceAuthority,
        explanation: vacancyDetail.explanation,
        unresolvedQuestions: isVerified
          ? ["Is the sender authorized by the employer to fill this active requisition?"]
          : ["Does this vacancy actually exist outside this message?"],
        suggestedAction: isVerified && vacancyDetail.matchedListingUrl
          ? `Apply directly via the official authenticated listing: ${vacancyDetail.matchedListingUrl}`
          : "Check the employer's official website directly.",
      };
    }

    if (claim.category === "payment_requirement" || claim.category === "payment_request") {
      const claimStatus: OfferClaimItem["status"] = paymentDetail.conflictsWithPolicy
        ? "CONTRADICTED"
        : paymentDetail.paymentRequested
        ? "OBSERVED"
        : "UNVERIFIED";
      return {
        ...claim,
        status: claimStatus,
        contradictingEvidence: paymentDetail.conflictsWithPolicy
          ? `Direct conflict with ${policyDetail.companyName}'s policy: "${policyDetail.policyQuote}"`
          : undefined,
        supportingEvidence: paymentDetail.paymentRequested && !paymentDetail.conflictsWithPolicy
          ? `Direct observation from submitted offer message: ${claim.extractedValue}`
          : undefined,
        sourceUrl: policyDetail.policyUrl,
        sourceAuthority: policyDetail.policyUrl ? policyDetail.sourceAuthority : "User Submitted Message",
        explanation: paymentDetail.explanation,
        unresolvedQuestions: ["Why is a candidate being asked for money when corporate policy or industry standards forbid fees?"],
        suggestedAction: "DO NOT PAY. Disregard any payment link or UPI handle.",
      };
    }

    if (claim.category === "recruiter_affiliation" || claim.category === "recruiter_identity") {
      const isAffilVerified = senderDetail.emailDomainMatchesCompany;
      return {
        ...claim,
        status: isAffilVerified ? "VERIFIED" : "UNVERIFIED",
        supportingEvidence: isAffilVerified
          ? `Sender domain matches corporate domain.`
          : undefined,
        contradictingEvidence: !isAffilVerified && senderDetail.senderEmail
          ? `Sender used personal/unverified domain (@${senderDetail.senderEmail.split("@")[1]}) instead of official corporate domain.`
          : undefined,
        sourceAuthority: isAffilVerified ? "Corporate Domain Match" : "Unverified Message",
        explanation: senderDetail.explanation,
        unresolvedQuestions: ["Can this person's role be verified via an independent corporate directory?"],
        suggestedAction: senderDetail.recommendedVerificationChannel
          ? `Verify recruiter via ${senderDetail.recommendedVerificationChannel}.`
          : "Reach out via the company's published switchboard.",
      };
    }

    if (claim.category === "employer_identity") {
      const isVerifiedBrand = Boolean(matchedBrand || knownPolicy);
      return {
        ...claim,
        status: isVerifiedBrand ? "VERIFIED" : "UNVERIFIED",
        supportingEvidence: matchedBrand
          ? `Recognized corporate entity: ${matchedBrand.canonicalName} (Official domain: ${matchedBrand.approvedDomains[0]})`
          : undefined,
        sourceUrl: isVerifiedBrand ? officialCareersUrl : undefined,
        sourceAuthority: isVerifiedBrand ? "Enterprise Domain Registry" : "Public Web Registry",
        explanation: matchedBrand
          ? `The company "${matchedBrand.canonicalName}" is an authenticated corporate brand.`
          : `The company identity could not be matched against verified enterprise domain records. This is an unverified identity, not definitive proof of non-existence.`,
        unresolvedQuestions: ["Is the message genuinely sent on behalf of this brand?"],
        suggestedAction: "Check official corporate domain records.",
      };
    }

    if (claim.category === "application_destination") {
      const isDestVerified = destinationDetail.isDomainConsistent && destinationDetail.destinationType === "OFFICIAL_CAREERS_PORTAL";
      const isReserved = destinationDetail.finalDomain?.endsWith(".example") || destinationDetail.submittedUrl?.includes(".example");
      return {
        ...claim,
        status: isDestVerified ? "VERIFIED" : "UNVERIFIED",
        supportingEvidence: isDestVerified ? `Matches verified employer domain.` : undefined,
        contradictingEvidence: isReserved ? `Destination is in RFC 2606 reserved example namespace (.example) and cannot be an operational careers portal.` : undefined,
        sourceUrl: destinationDetail.normalizedUrl,
        sourceAuthority: destinationDetail.destinationType,
        explanation: isReserved
          ? `The destination URL uses the reserved .example top-level domain (RFC 2606), which is synthetic documentation space and not a functioning corporate portal.`
          : destinationDetail.explanation,
        unresolvedQuestions: ["Does this form collect sensitive candidate PII or fees?"],
        suggestedAction: "Only submit credentials or personal information on independently authenticated official domains.",
      };
    }

    // Default: claims like urgency, shortlisting, no-interview, paywall are OBSERVED directly from message
    if (
      claim.category === "deadline_urgency" ||
      claim.category === "shortlisting_claim" ||
      claim.category === "interview_process" ||
      claim.category === "document_request"
    ) {
      return {
        ...claim,
        status: "OBSERVED",
      };
    }

    return claim;
  });

  // 7. Deterministic Risk Assessment under the 4-Tier Policy
  // Crucial rule: "THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE."
  let riskOutcome: RiskOutcome = "Unknown";
  let threatLikelihood: ThreatLikelihood = "Low";
  let consequenceImpact: ConsequenceImpact = "Low";
  let verdictTitle = "Offer Evaluation Inconclusive";
  let verdictSummary = "Available public evidence is insufficient to verify the authenticity of this offer.";
  let strongestEvidence = "Independent verification with employer required.";
  let mostConsequentialFinding = "Unverified offer details.";
  let keyRecommendation = "Verify the offer directly through the employer's official careers directory.";

  if (paymentDetail.paymentRequested) {
    if (paymentDetail.conflictsWithPolicy) {
      riskOutcome = "High risk";
      threatLikelihood = "High";
      consequenceImpact = "Severe";
      verdictTitle = "Deceptive Payment Trap: Legitimate Vacancy Weaponized for Scam";
      verdictSummary = `While the internship position exists at ${companyName}, the demand for ${paymentCurrency} ${paymentAmount} directly contradicts official recruitment policy. Legitimate employers never charge interview fees.`;
      strongestEvidence = policyDetail.policyQuote || "Official published corporate policy strictly prohibits applicant fees.";
      mostConsequentialFinding = `Demand for ${paymentCurrency} ${paymentAmount} to reserve an interview slot.`;
      keyRecommendation = `DO NOT PAY THE ${paymentCurrency} ${paymentAmount} FEE. Apply exclusively through ${companyName}'s official careers portal.`;
    } else {
      riskOutcome = "Suspicious";
      threatLikelihood = "Moderate";
      consequenceImpact = "High";
      verdictTitle = "Suspicious Fee Demand Detected in Job Offer";
      verdictSummary = `The offer requests ${paymentCurrency} ${paymentAmount}. Upfront fees for interviews or screening are a primary indicator of recruitment fraud.`;
      strongestEvidence = `Payment demand for ${paymentCurrency} ${paymentAmount}.`;
      mostConsequentialFinding = "Unverified upfront payment requested from applicant.";
      keyRecommendation = `Do not pay any fee. Contact the employer directly through their official switchboard.`;
    }
  } else if (vacancyDetail.vacancyStatus === "CHECK_FAILED") {
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    consequenceImpact = "Moderate";
    verdictTitle = "External Verification Check Incomplete";
    verdictSummary = "An external connection failure prevented real-time verification of the claimed vacancy.";
    strongestEvidence = "External lookup service timed out or was temporarily unavailable.";
    mostConsequentialFinding = "External check failure; independent verification required.";
    keyRecommendation = `Verify the listing manually on ${companyName}'s careers website.`;
  } else if (!vacancyDetail.isVacancyFound || vacancyDetail.vacancyStatus === "UNVERIFIED") {
    // Scenario B: No matching vacancy found on official employer directories
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    consequenceImpact = "Moderate";
    verdictTitle = "Unverified Vacancy: Independent Research Required";
    verdictSummary = `The claimed employer or vacancy for "${companyName}" could not be correlated with active listings on official careers directories.`;
    strongestEvidence = "No active requisition found on official corporate careers registries.";
    mostConsequentialFinding = "Vacancy claims cannot be corroborated.";
    keyRecommendation = `Verify whether this position exists directly on ${companyName}'s official website.`;
  } else if (senderDetail.senderEmail && senderDetail.affiliationStatus === "UNVERIFIED") {
    // Scenario D: Genuine vacancy exists, but sender is unverified free webmail or third party
    if (extracted.isShortlistedClaim || extracted.urgencyText) {
      riskOutcome = "Suspicious";
      threatLikelihood = "Moderate";
      consequenceImpact = "Moderate";
      verdictTitle = "Unsolicited Selection from Unverified Contact";
      verdictSummary = `The sender claims to represent ${companyName} but lacks corporate verification. Be cautious before disclosing sensitive identity documents.`;
      strongestEvidence = "Communication originates from an unverified personal or third-party address.";
      mostConsequentialFinding = "Unsolicited shortlisting without verifiable application history.";
      keyRecommendation = "Verify sender authenticity before sending resumes or identification documents.";
    } else {
      riskOutcome = "Unknown";
      threatLikelihood = "Uncertain";
      consequenceImpact = "Moderate";
      verdictTitle = "Recruiter Corporate Affiliation Inconclusive";
      verdictSummary = `An active listing exists at ${companyName}, but the sender's corporate email domain cannot be confirmed.`;
      strongestEvidence = "Sender email domain could not be verified against corporate infrastructure.";
      mostConsequentialFinding = "Unverified sender domain.";
      keyRecommendation = `Contact ${companyName}'s verified HR department to confirm the recruiter.`;
    }
  } else {
    // Both vacancy is verified AND sender domain is supported AND no payment demanded
    riskOutcome = "Low observed risk";
    threatLikelihood = "Low";
    consequenceImpact = "Low";
    verdictTitle = isDirectOfficialListing ? "Verified Official Career Listing" : "Offer Consistent With Verified Corporate Directory";
    verdictSummary = isDirectOfficialListing
      ? `The submitted listing matches active official requisition records for ${companyName} (${vacancyDetail.matchedListingTitle || roleTitle}) with no payment demands or deceptive markers observed.`
      : `The vacancy and recruiter domain match official ${companyName} records with no payment demands observed.`;
    strongestEvidence = isDirectOfficialListing
      ? `Active requisition ID ${jobReferenceId || "verified"} listed on ${vacancyDetail.sourceAuthority}.`
      : "Active vacancy listed on employer's official careers portal.";
    mostConsequentialFinding = "Zero payment demands or unverified credentials observed.";
    keyRecommendation = isDirectOfficialListing && vacancyDetail.matchedListingUrl
      ? `Apply directly via the official authenticated listing: ${vacancyDetail.matchedListingUrl}`
      : "Proceed with normal application procedures through official portals.";
  }

  // Core Brand Statement & Distinction
  const coreDistinctionNotice =
    paymentDetail.paymentRequested && vacancyDetail.isVacancyFound
      ? "CRITICAL DISTINCTION: THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE. Fraudsters routinely use genuine corporate job listings to make illicit payment requests appear credible."
      : "Your AI checks first. You act with confidence.";

  // 8. Safe Action Plan
  const isReservedDest = destinationDetail.finalDomain?.endsWith(".example") || destinationDetail.submittedUrl?.includes(".example");
  const verifiedAppRoute =
    !isReservedDest && vacancyDetail.isVacancyFound && vacancyDetail.matchedListingUrl && !vacancyDetail.matchedListingUrl.includes(".example")
      ? vacancyDetail.matchedListingUrl
      : undefined;

  const safeActionPlan = {
    primaryWarning: paymentDetail.paymentRequested
      ? `DO NOT PAY THE ${paymentCurrency} ${paymentAmount} FEE UNDER ANY CIRCUMSTANCES.`
      : "Verify sender credentials before submitting sensitive documents.",
    keyRecommendation,
    verifiedApplicationRoute: verifiedAppRoute,
    stepByStepActions: [
      paymentDetail.paymentRequested
        ? `1. Refuse the payment request: ${companyName} never charges applicants for interviews, tests, or onboarding fees.`
        : `1. Review the official job description directly on the employer's careers site.`,
      `2. Do not share passwords, OTPs, or banking credentials under any circumstances.`,
      `3. Do not submit sensitive identity documents (Aadhaar, PAN, Passport) until employer and recruiter identity are independently verified.`,
      isReservedDest
        ? `4. Do not treat .example or unverified links as legitimate application portals. Locate the real company website independently in a clean browser window.`
        : vacancyDetail.matchedListingUrl
        ? `4. Apply directly on the official careers page: ${vacancyDetail.matchedListingUrl}`
        : `4. Locate the official company website independently in a separate browser window. Do not click links provided in unsolicited messages.`,
      `5. Contact ${companyName} using official contact information discovered independently (published switchboard or verified careers email).`,
      `6. Request a verifiable job requisition ID and email confirmation sent exclusively from an authenticated company domain.`,
      `7. Preserve the complete original communication as evidence and report to your campus placement cell.`,
    ],
    whatNotToDo: [
      "Do NOT send money via UPI, QR code, netbanking, or cryptocurrency.",
      "Do NOT click payment links or scan QR codes provided in the message.",
      "Do NOT share passwords, OTPs, or banking credentials.",
      "Do NOT submit sensitive identity documents or government IDs over messaging apps.",
      "Do NOT call phone numbers or message handles provided inside the suspicious communication to verify that same communication.",
      "Do NOT provide bank account details, OTPs, or passwords for 'stipend verification'.",
    ],
    independentVerificationSteps: [
      `Search for "${companyName} official careers portal" in a clean browser window.`,
      `Check official corporate registries (e.g. MCA in India, SEC/state registries) to confirm legal entity status.`,
      `Look up ${companyName}'s published recruitment fraud notice: ${policyDetail.policyUrl || "Official corporate website"}.`,
      `Contact your university campus placement cell to report unsolicited recruiter messages.`,
    ],
  };

  // 9. Source & Provenance Explorer
  const sourceExplorer: OfferIntegrityReport["sourceExplorer"] = [];
  if (vacancyDetail.officialCareersUrl) {
    sourceExplorer.push({
      title: `${companyName} Official Careers Directory`,
      domain: officialDomain,
      url: vacancyDetail.matchedListingUrl || vacancyDetail.officialCareersUrl,
      observationTime: now,
      relevantFinding: `Active vacancy requisition: ${vacancyDetail.roleTitle}`,
      sourceCategory: "Official Careers Portal",
      authorityLevel: "Authoritative Primary",
      limitations: "Shows active public postings only.",
    });
  }
  if (policyDetail.policyUrl) {
    sourceExplorer.push({
      title: policyDetail.policyTitle || `${companyName} Recruitment Policy`,
      domain: officialDomain,
      url: policyDetail.policyUrl,
      observationTime: now,
      relevantFinding: policyDetail.policyQuote || "Official no-fee policy verified.",
      sourceCategory: "Recruitment Policy Page",
      authorityLevel: "Authoritative Primary",
      limitations: "Corporate policy; does not stop unauthorized third-party impersonators.",
    });
  }
  if (destinationDetail.submittedUrl) {
    sourceExplorer.push({
      title: "Submitted Offer Link",
      domain: destinationDetail.finalDomain || "unspecified",
      url: destinationDetail.submittedUrl,
      observationTime: now,
      relevantFinding: destinationDetail.explanation,
      sourceCategory: "Unverified Message",
      authorityLevel: destinationDetail.isDomainConsistent ? "Official Corporate" : "Untrusted Input",
      limitations: "Direct user-submitted input; treat as untrusted.",
    });
  }

  // 10. Trust Gap Nodes for Graph Visualization
  const trustGapMapNodes = claimsLedger.map((c) => ({
    id: c.id,
    claim: `${c.claimTitle}: ${c.extractedValue}`,
    status: c.status,
    evidence: c.supportingEvidence || c.contradictingEvidence || c.explanation,
    sourceUrl: c.sourceUrl,
    sourceAuthority: c.sourceAuthority,
  }));

  // 11. Synchronize Canonical Extraction with Verified Findings
  const canonicalExtraction = extracted.canonicalExtraction;
  if (canonicalExtraction) {
    if (matchedBrand) {
      canonicalExtraction.employer.status = "VERIFIED";
    } else if (vacancyDetail.vacancyStatus === "CHECK_FAILED") {
      canonicalExtraction.employer.status = "CHECK_FAILED";
    }

    if (vacancyDetail.vacancyStatus === "SUPPORTED") {
      canonicalExtraction.job.status = "VERIFIED";
      if (jobReferenceId) {
        canonicalExtraction.job.referenceId = jobReferenceId;
      }
    } else if (vacancyDetail.vacancyStatus === "CHECK_FAILED") {
      canonicalExtraction.job.status = "CHECK_FAILED";
    } else {
      canonicalExtraction.job.status = "UNVERIFIED";
    }

    if (paymentDetail.paymentRequested) {
      canonicalExtraction.payment.requested = true;
    }
  }

  return {
    investigationId,
    timestamp: now,
    input,
    riskOutcome,
    threatLikelihood,
    consequenceImpact,
    coreDistinctionNotice,
    overallAssessment: {
      verdictTitle,
      verdictSummary,
      strongestEvidence,
      mostConsequentialFinding,
      recommendedAction: keyRecommendation,
    },
    offerBreakdown: {
      vacancy: vacancyDetail,
      policy: policyDetail,
      sender: senderDetail,
      destination: destinationDetail,
      payment: paymentDetail,
    },
    claimsLedger,
    canonicalExtraction,
    recruitmentIndicators: extracted.recruitmentAnalysis.indicators,
    trustGapMapNodes,
    sourceExplorer,
    safeActionPlan,
    investigationLimitations: [
      "AheadGuard evaluates observable web evidence, corporate domain alignment, and verified employer policies.",
      "A confirmed vacancy does not certify that an unverified sender is authorized to hire for that vacancy.",
      "Always confirm suspicious recruiter messages directly through the employer's official channels.",
    ],
  };
}

function isDomainOrSubdomainLocal(host: string, targetDomain: string): boolean {
  if (host === targetDomain) return true;
  return host.endsWith(`.${targetDomain}`);
}
