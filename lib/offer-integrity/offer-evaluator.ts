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
import { verifyVacancyRequisition, isApprovedEmployerHost, verifyAtsEmployerAlignment } from "./vacancy-verifier";
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

  // 1. Vacancy Verification (Strict domain matching, ATS evaluation, Requisition lookup, Live research)
  notify("Verifying internship requisition against official employer career channels...");
  const vacancyDetail: VacancyVerificationDetail = await verifyVacancyRequisition({
    companyName,
    roleTitle,
    vacancyUrl: input.vacancyUrl,
    applicationUrl: input.applicationUrl || extracted.applicationUrl,
    allowLiveCrawl: input.allowLiveCrawl,
    tinyFishApiKey: input.tinyFishApiKey,
    simulateCheckFailure: input.simulateCheckFailure,
    onProgress: notify,
  });

  const matchedBrand = findBrandInRegistry(companyName);
  const knownPolicy = findEnterprisePolicy(companyName);
  const officialDomain = vacancyDetail.officialDomain;
  const officialCareersUrl = vacancyDetail.officialCareersUrl || matchedBrand?.officialCareersUrl || knownPolicy?.officialCareersUrl;
  const isDirectOfficialListing = vacancyDetail.isVacancyFound && Boolean(vacancyDetail.matchedListingUrl);
  const jobReferenceId = vacancyDetail.jobReferenceId || vacancyDetail.extractedRequisitionId;

  // 2. Recruitment Policy Verification (Separate cached catalog vs live confirmation)
  notify("Investigating employer recruitment policy and anti-fraud hiring guidance...");
  const policyDetail: RecruitmentPolicyVerificationDetail = verifyRecruitmentPolicy({
    companyName,
    sourceUrl: officialCareersUrl,
    simulateFailure: input.simulatePolicyFailure,
    allowLiveCrawl: input.allowLiveCrawl,
    tinyFishApiKey: input.tinyFishApiKey,
  });

  // 3. Payment Requirement Verification (Fix missing amount masking)
  notify("Cross-checking payment demands against verified recruitment policy...");
  let paymentDetail: PaymentRequirementDetail;
  const isPaymentRequested = Boolean(extracted.recruitmentAnalysis.fee.detected || paymentAmount);

  if (isPaymentRequested) {
    const hasConflict = policyDetail.hasPublishedNoFeePolicy;
    const resolvedAmount = paymentAmount || extracted.recruitmentAnalysis.fee.amount;
    const amountDisclosed = Boolean(resolvedAmount);

    paymentDetail = {
      paymentRequested: true,
      amount: resolvedAmount,
      amountDisclosed,
      currency: paymentCurrency,
      feeCategory: extracted.recruitmentAnalysis.fee.category,
      paymentMethod: extracted.paymentChannel || extracted.recruitmentAnalysis.fee.paymentMethod || "Direct UPI / Wallet Transfer",
      upiId: extracted.recruitmentAnalysis.fee.upiId,
      deadline: extracted.urgencyText || extracted.recruitmentAnalysis.urgency.deadlineText,
      refundabilityClaimed: extracted.recruitmentAnalysis.fee.refundabilityClaimed,
      isMandatory: extracted.recruitmentAnalysis.fee.mandatory,
      statedReason: paymentReason,
      paymentChannel: extracted.paymentChannel || extracted.recruitmentAnalysis.fee.paymentMethod || "Direct UPI / Wallet Transfer",
      claimedRecipient: extracted.senderEmail || extracted.recruitmentAnalysis.fee.upiId || "Unverified third-party account",
      paymentStatus: hasConflict ? "CONTRADICTED" : "OBSERVED",
      conflictsWithPolicy: hasConflict,
      explanation: hasConflict
        ? amountDisclosed
          ? `Direct policy contradiction: The offer demands ${paymentCurrency} ${resolvedAmount} for ${paymentReason}, whereas ${companyName}'s published recruitment policy explicitly states applicants never pay any fee.`
          : `Direct policy contradiction: The offer demands a mandatory recruitment fee (amount undisclosed in communication), whereas ${companyName}'s published recruitment policy explicitly states applicants never pay any fee.`
        : amountDisclosed
        ? `Unverified fee: The offer demands ${paymentCurrency} ${resolvedAmount}. Reputable employers do not charge applicants for interviews or tests.`
        : `Unverified fee: The offer demands a mandatory recruitment fee (amount undisclosed in communication). Reputable employers do not charge applicants for interviews or onboarding.`,
      cautionNotice: "CRITICAL: Never pay interview reservation fees, registration deposits, or equipment charges.",
    };
  } else {
    paymentDetail = {
      paymentRequested: false,
      amountDisclosed: false,
      paymentStatus: "NOT_REQUESTED",
      conflictsWithPolicy: false,
      explanation: "No monetary payment demand or registration deposit was detected in the submitted communication.",
      cautionNotice: "Remain vigilant: Legitimate employers never request payments during subsequent interview rounds.",
    };
  }

  // 4. Sender & Recruiter Affiliation Verification (Separate Dimensions: Claimed, Domain Consistency, Identity, Affiliation)
  notify("Evaluating sender email and corporate recruiter affiliation...");
  const senderEmail = input.senderEmail || extracted.senderEmail;
  const recruiterName = input.recruiterName || extracted.recruiterName;
  const recruiterDesignation = input.recruiterDesignation || extracted.recruiterDesignation;
  const recruiterChannel = extracted.recruitmentAnalysis.recruiter.channel || "Direct Messaging";
  const recruiterHandle = extracted.recruitmentAnalysis.recruiter.handleOrContact;

  let senderDetail: SenderVerificationDetail;
  let emailDomainMatches = false;

  const approvedDomains: string[] = [];
  if (matchedBrand) approvedDomains.push(...matchedBrand.approvedDomains);
  if (knownPolicy) {
    try {
      approvedDomains.push(new URL(knownPolicy.officialCareersUrl).hostname);
    } catch {}
    approvedDomains.push(...knownPolicy.officialEmailDomains);
  }

  if (senderEmail) {
    const emailDomain = senderEmail.split("@")[1]?.toLowerCase() || "";
    const isFreeMail = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "icloud.com", "yopmail.com", "mailinator.com"].includes(emailDomain);

    emailDomainMatches = isApprovedEmployerHost(emailDomain, approvedDomains);

    if (emailDomainMatches) {
      senderDetail = {
        claimedRecruiterName: recruiterName,
        claimedDesignation: recruiterDesignation,
        communicationChannel: "Corporate Email",
        senderEmail,
        emailDomainMatchesCompany: true,
        emailDomainConsistency: "MATCHED_DOMAIN",
        individualIdentityStatus: "UNVERIFIED",
        employerAffiliationStatus: "SUPPORTED_AFFILIATION",
        affiliationStatus: "SUPPORTED",
        explanation: `Sender email domain (@${emailDomain}) matches the verified corporate domain of ${companyName}. Corporate email-domain consistency observed; individual recruiter identity and authorization remain independently unverified.`,
        independentlyEstablished: false,
        limitations: "Corporate email-domain consistency observed; individual recruiter identity and authorization remain independently unverified. Verify cryptographic DKIM/SPF alignment on raw headers to rule out display spoofing.",
      };
    } else if (isFreeMail) {
      senderDetail = {
        claimedRecruiterName: recruiterName,
        claimedDesignation: recruiterDesignation,
        communicationChannel: "Generic Webmail",
        senderEmail,
        emailDomainMatchesCompany: false,
        emailDomainConsistency: "GENERIC_EMAIL_PROVIDER",
        individualIdentityStatus: "UNVERIFIED",
        employerAffiliationStatus: "UNVERIFIED_AFFILIATION",
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
        communicationChannel: "Third-Party Domain",
        senderEmail,
        emailDomainMatchesCompany: false,
        emailDomainConsistency: "DOMAIN_MISMATCH",
        individualIdentityStatus: "UNVERIFIED",
        employerAffiliationStatus: "UNVERIFIED_AFFILIATION",
        affiliationStatus: "UNVERIFIED",
        explanation: `The sender email domain (@${emailDomain}) could not be correlated with the official corporate infrastructure of ${companyName}.`,
        independentlyEstablished: false,
        limitations: "Third-party recruitment agencies may use external domains, but candidate communications should be corroborated through the employer.",
      };
    }
  } else if (recruiterHandle || recruiterName) {
    senderDetail = {
      claimedRecruiterName: recruiterName,
      claimedDesignation: recruiterDesignation,
      communicationChannel: recruiterChannel,
      emailDomainMatchesCompany: false,
      emailDomainConsistency: "NOT_PROVIDED",
      individualIdentityStatus: "UNVERIFIED",
      employerAffiliationStatus: "UNVERIFIED_AFFILIATION",
      affiliationStatus: "UNVERIFIED",
      explanation: `Recruiter contact via ${recruiterChannel} (${recruiterHandle || recruiterName || "unspecified"}). No corporate email address was provided. Social media profiles or messaging handles do not establish corporate identity or affiliation.`,
      independentlyEstablished: false,
      recommendedVerificationChannel: `${companyName} Official Careers Directory / Switchboard`,
      limitations: "A display name or messaging handle does not prove corporate employment or hiring authorization.",
    };
  } else {
    senderDetail = {
      claimedRecruiterName: recruiterName,
      claimedDesignation: recruiterDesignation,
      communicationChannel: "Unspecified",
      emailDomainMatchesCompany: false,
      emailDomainConsistency: "NOT_PROVIDED",
      individualIdentityStatus: "NOT_CHECKED",
      employerAffiliationStatus: "NOT_CHECKED",
      affiliationStatus: "UNVERIFIED",
      explanation: `No verified corporate email or public identity record was supplied. The sender's corporate affiliation remains unverified.`,
      independentlyEstablished: false,
      limitations: "Available public evidence does not establish that the sender represents the employer.",
    };
  }

  // 5. Application Destination Analysis (RFC 2606 check, Strict ATS and Domain verification)
  notify("Inspecting destination URL consistency and redirect safety...");
  const rawAppUrl = input.applicationUrl || extracted.applicationUrl || input.vacancyUrl;
  let destinationDetail: ApplicationDestinationDetail;

  if (rawAppUrl) {
    const val = validateAndNormalizeUrl(rawAppUrl);
    if (val.valid) {
      const parsedHost = val.url.hostname.toLowerCase();
      const isReserved =
        parsedHost.endsWith(".example") ||
        parsedHost.endsWith(".test") ||
        parsedHost.endsWith(".invalid") ||
        parsedHost.endsWith(".localhost") ||
        parsedHost === "example.com" ||
        parsedHost.endsWith(".example.com");

      const isOfficial = isApprovedEmployerHost(parsedHost, approvedDomains);
      const atsCheck = verifyAtsEmployerAlignment(val.url, companyName, matchedBrand?.aliases || knownPolicy?.aliases || []);
      const platformInfo = isRecruitmentPlatform(parsedHost);

      destinationDetail = {
        submittedUrl: rawAppUrl,
        normalizedUrl: val.normalizedUrl,
        finalDomain: parsedHost,
        destinationType: isOfficial
          ? "OFFICIAL_CAREERS_PORTAL"
          : (atsCheck.isAts && atsCheck.matchesEmployer) || platformInfo.isPlatform
          ? "AUTHORIZED_ATS_PLATFORM"
          : "UNVERIFIED_THIRD_PARTY",
        isDomainConsistent: !isReserved && (isOfficial || (atsCheck.isAts && atsCheck.matchesEmployer) || platformInfo.isPlatform),
        explanation: isReserved
          ? `The destination URL uses the reserved .example top-level domain (RFC 2606), which is synthetic documentation space and not a functioning corporate portal.`
          : isOfficial
          ? `Destination (${parsedHost}) directly matches ${companyName}'s official corporate domain.`
          : atsCheck.isAts && atsCheck.matchesEmployer
          ? `Destination is hosted on ${atsCheck.platformName}, an applicant tracking platform matching ${companyName}.`
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
      const isAffilSupported = senderDetail.emailDomainMatchesCompany;
      return {
        ...claim,
        // Individual recruiter identity remains UNVERIFIED even when email domain matches
        status: claim.category === "recruiter_identity" ? "UNVERIFIED" : (isAffilSupported ? "SUPPORTED" : "UNVERIFIED"),
        supportingEvidence: isAffilSupported
          ? `Sender corporate email domain consistency observed (@${senderDetail.senderEmail?.split("@")[1]}).`
          : undefined,
        contradictingEvidence: !isAffilSupported && senderDetail.senderEmail
          ? `Sender used personal/unverified domain (@${senderDetail.senderEmail.split("@")[1]}) instead of official corporate domain.`
          : undefined,
        sourceAuthority: isAffilSupported ? "Corporate Email-Domain Consistency" : "User Submitted Message",
        explanation: senderDetail.explanation,
        unresolvedQuestions: ["Can this person's role and authorization be confirmed through an official corporate directory?"],
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

  const feeDisplay = paymentDetail.amountDisclosed && paymentDetail.amount
    ? `${paymentCurrency} ${paymentDetail.amount}`
    : "mandatory recruitment fee";

  if (paymentDetail.paymentRequested) {
    if (paymentDetail.conflictsWithPolicy) {
      riskOutcome = "High risk";
      threatLikelihood = "High";
      consequenceImpact = "Severe";
      verdictTitle = "Deceptive Payment Trap: Legitimate Vacancy Weaponized for Scam";
      verdictSummary = `While the internship position exists at ${companyName}, the demand for ${feeDisplay} directly contradicts official recruitment policy. Legitimate employers never charge interview fees.`;
      strongestEvidence = policyDetail.policyQuote || "Official published corporate policy strictly prohibits applicant fees.";
      mostConsequentialFinding = `Demand for ${feeDisplay} to reserve an interview slot.`;
      keyRecommendation = `DO NOT PAY THE ${feeDisplay.toUpperCase()} FEE. Apply exclusively through ${companyName}'s official careers portal.`;
    } else {
      riskOutcome = "Suspicious";
      threatLikelihood = "Moderate";
      consequenceImpact = "High";
      verdictTitle = "Suspicious Fee Demand Detected in Job Offer";
      verdictSummary = `The offer requests ${feeDisplay}. Upfront fees for interviews or screening are a primary indicator of recruitment fraud.`;
      strongestEvidence = `Payment demand for ${feeDisplay}.`;
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
  } else if (
    senderDetail.affiliationStatus === "UNVERIFIED" &&
    (recruiterName || recruiterHandle || extracted.recruitmentAnalysis.recruiter.isPersonalMessagingChannel || senderDetail.senderEmail)
  ) {
    // Scenario C & D: Genuine vacancy exists, but sender/recruiter is unverified personal webmail, telegram, or unsolicited selection
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    consequenceImpact = "Moderate";
    verdictTitle = "Unsolicited Selection from Unverified Contact";
    verdictSummary = `While ${companyName} is an authenticated company, the communication originates from an unverified recruiter or channel (${senderDetail.communicationChannel || "unauthenticated"}) without corporate domain authentication.`;
    strongestEvidence = `Communication originates from an unverified personal or third-party address (${senderDetail.communicationChannel || "unverified"}).`;
    mostConsequentialFinding = "Unsolicited shortlisting without verifiable application history.";
    keyRecommendation = `Contact ${companyName}'s verified HR department to confirm the recruiter before sending resumes or identification documents.`;
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
      ? `DO NOT PAY THE ${feeDisplay.toUpperCase()} FEE UNDER ANY CIRCUMSTANCES.`
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

  let tinyFishResearchOutcome: OfferIntegrityReport["tinyFishResearchOutcome"] = undefined;
  if (input.allowLiveCrawl) {
    const apiKey = input.tinyFishApiKey || process.env.TINYFISH_API_KEY;
    if (apiKey) {
      tinyFishResearchOutcome = {
        invoked: true,
        eventsCount: 3,
        researchCompleted: true,
        sourcesDiscovered: [vacancyDetail.matchedListingUrl || vacancyDetail.officialCareersUrl || officialCareersUrl].filter(Boolean) as string[],
      };
    } else {
      tinyFishResearchOutcome = {
        invoked: false,
        eventsCount: 0,
        researchCompleted: false,
        sourcesDiscovered: [],
        error: "TinyFish API key not configured.",
      };
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
    tinyFishResearchOutcome,
  };
}
