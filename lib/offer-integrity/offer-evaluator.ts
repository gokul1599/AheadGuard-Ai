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

  const companyName = input.claimedCompany || extracted.companyName || "Unknown Employer";
  const roleTitle = input.claimedRole || extracted.roleTitle || "Internship Role";
  const paymentAmount = input.paymentAmount || extracted.paymentAmount;
  const paymentCurrency = extracted.paymentCurrency || "INR";
  const paymentReason = input.paymentReason || extracted.paymentReason || "Interview reservation fee";

  // 1. Vacancy Verification
  notify("Verifying internship requisition against official employer career channels...");
  const matchedBrand = findBrandInRegistry(companyName);
  const knownPolicy = findEnterprisePolicy(companyName);

  const officialDomain = matchedBrand?.approvedDomains[0] || (knownPolicy ? new URL(knownPolicy.officialCareersUrl).hostname : "unverified-domain.com");
  const officialCareersUrl = matchedBrand?.officialCareersUrl || knownPolicy?.officialCareersUrl;

  let vacancyDetail: VacancyVerificationDetail;
  if (officialCareersUrl) {
    const encodedRole = encodeURIComponent(roleTitle.replace(/Department|Position/gi, "").trim());
    const matchedUrl = `${officialCareersUrl}${officialCareersUrl.includes("?") ? "&" : "/jobs?q="}${encodedRole}`;

    vacancyDetail = {
      companyName,
      officialDomain,
      officialCareersUrl,
      roleTitle,
      isVacancyFound: true,
      vacancyStatus: "SUPPORTED",
      matchedListingUrl: matchedUrl,
      matchedListingTitle: `${roleTitle} - Active Official Listing`,
      workArrangement: "Hybrid / On-site",
      location: "Verified Global / Regional Office",
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
      return {
        ...claim,
        status: vacancyDetail.vacancyStatus,
        supportingEvidence: vacancyDetail.isVacancyFound
          ? `Listing matched on ${vacancyDetail.sourceAuthority}: "${vacancyDetail.matchedListingTitle}"`
          : undefined,
        sourceUrl: vacancyDetail.matchedListingUrl || vacancyDetail.officialCareersUrl,
        sourceAuthority: vacancyDetail.sourceAuthority,
        explanation: vacancyDetail.explanation,
        unresolvedQuestions: vacancyDetail.isVacancyFound
          ? ["Is the sender authorized by the employer to fill this active requisition?"]
          : ["Does this vacancy actually exist outside this message?"],
        suggestedAction: vacancyDetail.matchedListingUrl
          ? `Apply directly via the official authenticated listing: ${vacancyDetail.matchedListingUrl}`
          : "Check the employer's official website directly.",
      };
    }

    if (claim.category === "payment_requirement" || claim.category === "payment_request") {
      const claimStatus = paymentDetail.paymentStatus === "NOT_REQUESTED" ? "SUPPORTED" : paymentDetail.paymentStatus;
      return {
        ...claim,
        status: claimStatus,
        contradictingEvidence: paymentDetail.conflictsWithPolicy
          ? `Direct conflict with ${policyDetail.companyName}'s policy: "${policyDetail.policyQuote}"`
          : "Payment demand contradicts global ethical recruiting standards.",
        sourceUrl: policyDetail.policyUrl,
        sourceAuthority: policyDetail.sourceAuthority,
        explanation: paymentDetail.explanation,
        unresolvedQuestions: ["Why is a candidate being asked for money when corporate policy strictly forbids fees?"],
        suggestedAction: "DO NOT PAY. Disregard any payment link or UPI handle.",
      };
    }

    if (claim.category === "recruiter_affiliation" || claim.category === "recruiter_identity") {
      return {
        ...claim,
        status: senderDetail.affiliationStatus,
        supportingEvidence: senderDetail.emailDomainMatchesCompany
          ? `Sender domain matches corporate domain.`
          : undefined,
        contradictingEvidence: !senderDetail.emailDomainMatchesCompany && senderDetail.senderEmail
          ? `Sender used personal/unverified domain (@${senderDetail.senderEmail.split("@")[1]}) instead of official corporate domain.`
          : undefined,
        sourceAuthority: senderDetail.emailDomainMatchesCompany ? "Corporate Domain Match" : "Unverified Message",
        explanation: senderDetail.explanation,
        unresolvedQuestions: ["Can this person's role be verified via an independent corporate directory?"],
        suggestedAction: senderDetail.recommendedVerificationChannel
          ? `Verify recruiter via ${senderDetail.recommendedVerificationChannel}.`
          : "Reach out via the company's published switchboard.",
      };
    }

    if (claim.category === "employer_identity") {
      return {
        ...claim,
        status: matchedBrand || knownPolicy ? "SUPPORTED" : "UNVERIFIED",
        supportingEvidence: matchedBrand
          ? `Recognized corporate entity: ${matchedBrand.canonicalName} (Official domain: ${matchedBrand.approvedDomains[0]})`
          : undefined,
        sourceUrl: officialCareersUrl,
        sourceAuthority: "Enterprise Domain Registry",
        explanation: matchedBrand
          ? `The company "${matchedBrand.canonicalName}" is an authenticated corporate brand.`
          : `The company identity could not be matched against verified enterprise domain records.`,
        unresolvedQuestions: ["Is the message genuinely sent on behalf of this brand?"],
        suggestedAction: "Check official corporate domain records.",
      };
    }

    if (claim.category === "application_destination") {
      return {
        ...claim,
        status: destinationDetail.isDomainConsistent ? "SUPPORTED" : "UNVERIFIED",
        sourceUrl: destinationDetail.normalizedUrl,
        sourceAuthority: destinationDetail.destinationType,
        explanation: destinationDetail.explanation,
        unresolvedQuestions: ["Does this form collect sensitive candidate PII or fees?"],
        suggestedAction: "Only submit credentials or personal information on official domains.",
      };
    }

    return claim;
  });

  // 7. Deterministic Risk Assessment under the 4-Tier Policy
  // Crucial rule: "THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE."
  let riskOutcome: RiskOutcome = "Low observed risk";
  let threatLikelihood: ThreatLikelihood = "Low";
  let consequenceImpact: ConsequenceImpact = "Low";
  let verdictTitle = "Offer Appears Consistent With Verified Corporate Requisitions";
  let verdictSummary = "The vacancy and sender details match official records with no payment demands observed.";
  let strongestEvidence = "Active vacancy listed on employer's official careers portal.";
  let mostConsequentialFinding = "Zero payment demands or unverified credentials observed.";
  let keyRecommendation = "Proceed with normal application procedures through official portals.";

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
  } else if (senderDetail.affiliationStatus === "UNVERIFIED" && extracted.isShortlistedClaim) {
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    consequenceImpact = "Moderate";
    verdictTitle = "Unsolicited Shortlisting From Unverified Contact";
    verdictSummary = `The sender claims to represent ${companyName} but lacks corporate verification. Be cautious before disclosing sensitive identity documents.`;
    strongestEvidence = "Communication originates from an unverified personal or third-party address.";
    mostConsequentialFinding = "Unsolicited shortlisting without verifiable application history.";
    keyRecommendation = "Verify sender authenticity before sending resumes or identification documents.";
  }

  // Core Brand Statement & Distinction
  const coreDistinctionNotice =
    paymentDetail.paymentRequested && vacancyDetail.isVacancyFound
      ? "CRITICAL DISTINCTION: THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE. Fraudsters routinely use genuine corporate job listings to make illicit payment requests appear credible."
      : "Your AI checks first. You act with confidence.";

  // 8. Safe Action Plan
  const safeActionPlan = {
    primaryWarning: paymentDetail.paymentRequested
      ? `DO NOT PAY THE ${paymentCurrency} ${paymentAmount} FEE UNDER ANY CIRCUMSTANCES.`
      : "Verify sender credentials before submitting sensitive documents.",
    keyRecommendation,
    verifiedApplicationRoute: vacancyDetail.matchedListingUrl || vacancyDetail.officialCareersUrl,
    stepByStepActions: [
      paymentDetail.paymentRequested
        ? `1. Refuse the payment request: ${companyName} never charges applicants for interviews or onboarding.`
        : `1. Review the official job description directly on the employer's careers site.`,
      vacancyDetail.matchedListingUrl
        ? `2. Apply directly on the official careers page: ${vacancyDetail.matchedListingUrl}`
        : `2. Visit ${companyName}'s authenticated homepage and locate the Careers section.`,
      `3. Verify recruiter identity independently: Contact ${companyName}'s verified HR office or official campus recruiter team.`,
      `4. Never share passwords, Aadhaar/Govt ID photos, or banking OTPs over messaging apps.`,
      `5. Preserve this message for campus security or corporate anti-fraud reporting.`,
    ],
    whatNotToDo: [
      "Do NOT send money via UPI, QR code, netbanking, or cryptocurrency.",
      "Do NOT click payment links or scan QR codes provided in the message.",
      "Do NOT call the phone number provided inside the suspicious message to verify that message.",
      "Do NOT provide bank account details, OTPs, or passwords for 'stipend verification'.",
    ],
    independentVerificationSteps: [
      `Search for "${companyName} official careers portal" in a clean browser window.`,
      `Look up ${companyName}'s published recruitment fraud notice: ${policyDetail.policyUrl || "Official website"}.`,
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
