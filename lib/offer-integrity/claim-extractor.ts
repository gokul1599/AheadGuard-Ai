import { OfferIntegrityInput, OfferClaimItem } from "./types";
import { BRAND_DOMAIN_REGISTRY } from "../policy";
import {
  analyzeRecruitmentBehavior,
  RecruitmentBehaviorAnalysis,
} from "../recruitment-intelligence";

export interface ExtractedOfferData {
  companyName?: string;
  roleTitle?: string;
  recruiterName?: string;
  recruiterDesignation?: string;
  senderEmail?: string;
  senderPhone?: string;
  paymentAmount?: string;
  paymentCurrency?: string;
  paymentReason?: string;
  paymentChannel?: string;
  applicationUrl?: string;
  urgencyText?: string;
  isShortlistedClaim: boolean;
  noInterviewClaim?: boolean;
  recruitmentAnalysis: RecruitmentBehaviorAnalysis;
  claims: OfferClaimItem[];
}

/**
 * Normalizes and extracts structured claim elements from an internship or job offer text.
 */
export function extractOfferClaims(input: OfferIntegrityInput): ExtractedOfferData {
  const text = (input.offerMessage || "").trim();
  const now = new Date().toISOString();

  // Run comprehensive Recruitment Behavior Intelligence Analysis
  const recruitmentAnalysis = analyzeRecruitmentBehavior({
    text,
    claimedCompany: input.claimedCompany,
    claimedRole: input.claimedRole,
    recruiterName: input.recruiterName,
    recruiterDesignation: input.recruiterDesignation,
    senderEmail: input.senderEmail,
    senderPhone: input.senderPhone,
    paymentAmount: input.paymentAmount,
    paymentReason: input.paymentReason,
    applicationUrl: input.applicationUrl,
    vacancyUrl: input.vacancyUrl,
  });

  // 1. Company Identification
  let companyName = input.claimedCompany?.trim();
  if (!companyName) {
    // Check known brands in registry
    for (const brand of Object.values(BRAND_DOMAIN_REGISTRY)) {
      const regex = new RegExp(`\\b${brand.canonicalName}\\b`, "i");
      if (regex.test(text)) {
        companyName = brand.canonicalName;
        break;
      }
      for (const alias of brand.aliases) {
        const aliasRegex = new RegExp(`\\b${alias}\\b`, "i");
        if (aliasRegex.test(text)) {
          companyName = brand.canonicalName;
          break;
        }
      }
      if (companyName) break;
    }

    // Heuristic company matching if still missing
    if (!companyName) {
      const compMatch = text.match(/(?:at|with|from|joining)\s+([A-Z][A-Za-z0-9&.\s]{2,25}?)(?:\s+(?:team|careers|department|technologies|corporation|inc|ltd|limited|solutions|\.|\,))/i);
      if (compMatch && compMatch[1]) {
        companyName = compMatch[1].trim();
      }
    }
  }

  // 2. Role / Internship Title Identification
  let roleTitle = input.claimedRole?.trim();
  if (!roleTitle) {
    const rolePatterns = [
      /(?:internship\s+in\s+our\s+([A-Za-z\s]+?)\s+department)/i,
      /(?:role\s+of\s+([A-Za-z\s]+?\s+intern(?:ship)?))/i,
      /(?:position\s+of\s+([A-Za-z\s]+?\s+intern(?:ship)?))/i,
      /([A-Z][A-Za-z\s]{2,30}?\s+Intern(?:ship)?)/,
      /(?:shortlisted\s+for\s+(?:an?\s+)?([A-Za-z\s]+?\s+intern(?:ship)?))/i,
      /(?:opportunity\s+as\s+(?:an?\s+)?([A-Za-z\s]+?\s+intern(?:ship)?))/i,
    ];
    for (const pat of rolePatterns) {
      const match = text.match(pat);
      if (match && match[1]) {
        roleTitle = match[1].trim();
        break;
      }
    }
    if (!roleTitle && /internship/i.test(text)) {
      roleTitle = "Internship Position";
    }
  }

  // 3. Recruiter Name & Designation
  let recruiterName = input.recruiterName?.trim();
  if (!recruiterName) {
    const recruiterMatch =
      text.match(/(?:Contact|I\s+am|This\s+is|from|reach\s+out\s+to)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s*,?\s*(?:from|HR|Talent|Recruiter|Campus|Hiring)/i) ||
      text.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s*,\s*(?:Campus\s+Recruiter|HR|Talent|Technical\s+Recruiter)/i);
    if (recruiterMatch && recruiterMatch[1]) {
      recruiterName = recruiterMatch[1].trim();
    } else {
      recruiterName = recruitmentAnalysis.recruiter.name;
    }
  }

  let recruiterDesignation = input.recruiterDesignation?.trim();
  if (!recruiterDesignation) {
    const desigMatch = text.match(/(Campus\s+Recruiter|HR\s+Manager|Talent\s+Acquisition(?:\s+Specialist)?|Technical\s+Recruiter|Hiring\s+Manager|People\s+Operations|Recruitment\s+Coordinator)/i);
    if (desigMatch && desigMatch[1]) {
      recruiterDesignation = desigMatch[1].trim();
    } else {
      recruiterDesignation = recruitmentAnalysis.recruiter.designation;
    }
  }

  // 4. Sender Email & Phone
  let senderEmail = input.senderEmail?.trim();
  if (!senderEmail) {
    const emailMatch = text.match(/([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/);
    if (emailMatch && emailMatch[1]) {
      senderEmail = emailMatch[1].toLowerCase().replace(/[.,;:]+$/, "").trim();
    }
  }

  let senderPhone = input.senderPhone?.trim();
  if (!senderPhone) {
    const phoneMatch = text.match(/(?:\+91[-\s]?)?[6789]\d{9}\b|\+?\d{1,3}[-\s]?\(?\d{2,4}\)?[-\s]?\d{3,4}[-\s]?\d{4}/);
    if (phoneMatch && phoneMatch[0]) {
      senderPhone = phoneMatch[0].trim();
    }
  }

  // 5. Payment Amount, Currency & Purpose (Enhanced via Recruitment Intelligence)
  const paymentAmount = input.paymentAmount?.trim() || recruitmentAnalysis.fee.amount;
  const paymentCurrency = recruitmentAnalysis.fee.currency || "INR";
  const paymentReason = input.paymentReason?.trim() || recruitmentAnalysis.fee.reason || "Registration and onboarding fee";
  const paymentChannel = recruitmentAnalysis.fee.paymentMethod || "Direct P2P Transfer";

  // 6. Application / Vacancy URL
  let applicationUrl = input.applicationUrl?.trim() || input.vacancyUrl?.trim();
  if (!applicationUrl) {
    const urlMatch = text.match(/https?:\/\/[^\s"'<>]+/i);
    if (urlMatch && urlMatch[0]) {
      applicationUrl = urlMatch[0].replace(/[.,;)]+$/, "");
    }
  }

  // 7. Urgency & Process Anomaly Extraction
  const urgencyText = recruitmentAnalysis.urgency.deadlineText || undefined;
  const isShortlistedClaim = /(?:congratulations|shortlisted|selected|chosen|qualif(?:y|ied))\s+(?:for|as)/i.test(text);
  const noInterviewClaim = recruitmentAnalysis.process.noInterviewRequired;

  // 8. Generate Material Offer Claims with Explicit Evidence Provenance
  const claims: OfferClaimItem[] = [];

  // Claim 1: Employer Identity (UNVERIFIED until corroborated by registry)
  if (companyName) {
    claims.push({
      id: "claim-offer-company",
      category: "employer_identity",
      claimTitle: "Claimed Employer Identity",
      extractedValue: companyName,
      status: "UNVERIFIED",
      observationTime: now,
      explanation: `The offer asserts association with or representation of ${companyName}.`,
      unresolvedQuestions: ["Does the sender originate from verified corporate infrastructure?"],
      suggestedAction: "Check official corporate domain records and security policies.",
    });
  }

  // Claim 2: Vacancy Existence (UNVERIFIED until corroborated by portal)
  if (roleTitle) {
    claims.push({
      id: "claim-offer-vacancy",
      category: "vacancy_existence",
      claimTitle: "Internship Requisition Existence",
      extractedValue: roleTitle,
      status: "UNVERIFIED",
      observationTime: now,
      explanation: `The message claims an active internship position for "${roleTitle}".`,
      unresolvedQuestions: ["Is this requisition actively indexed on the authenticated careers portal?"],
      suggestedAction: "Verify directly against the employer's official careers portal.",
    });
  }

  // Claim 3: Payment Request / Interview Fee (Directly OBSERVED in user's message)
  if (paymentAmount) {
    const formattedFee = `${paymentCurrency} ${paymentAmount}`;
    claims.push({
      id: "claim-offer-payment",
      category: "payment_requirement",
      claimTitle: "Mandatory Interview / Registration Fee",
      extractedValue: `${formattedFee}${paymentReason ? ` (${paymentReason})` : ""}`,
      status: "OBSERVED",
      observationTime: now,
      explanation: `The offer demands payment of ${formattedFee} prior to interview slot reservation or candidacy onboarding.`,
      unresolvedQuestions: ["Does the employer's published hiring policy allow applicant fees or slot reservation payments?"],
      suggestedAction: "Check the employer's published candidate guidance and anti-fraud hiring policy.",
    });
  }

  // Claim 4: Recruiter Identity / Affiliation (UNVERIFIED until corroborated by email/directory)
  if (recruiterName || senderEmail || recruitmentAnalysis.recruiter.handleOrContact) {
    const recruiterVal = [
      recruiterName,
      recruiterDesignation,
      recruitmentAnalysis.recruiter.handleOrContact ? `via ${recruitmentAnalysis.recruiter.channel || "Messaging"} (${recruitmentAnalysis.recruiter.handleOrContact})` : undefined,
      senderEmail,
    ].filter(Boolean).join(" - ");

    claims.push({
      id: "claim-offer-recruiter",
      category: "recruiter_affiliation",
      claimTitle: "Recruiter Corporate Affiliation",
      extractedValue: recruiterVal,
      status: "UNVERIFIED",
      observationTime: now,
      explanation: `The message sender claims to act as an authorized recruiter: "${recruiterVal}".`,
      unresolvedQuestions: ["Is the email from an authenticated corporate domain?", "Can the individual be confirmed on corporate staff registries?"],
      suggestedAction: "Confirm through official company switchboard or independently contacted HR department.",
    });
  }

  // Claim 5: Application Destination (UNVERIFIED until domain check completes)
  if (applicationUrl) {
    claims.push({
      id: "claim-offer-destination",
      category: "application_destination",
      claimTitle: "Application / Submission Portal",
      extractedValue: applicationUrl,
      status: "UNVERIFIED",
      observationTime: now,
      explanation: `The candidate is instructed to apply or submit details via ${applicationUrl}.`,
      unresolvedQuestions: ["Does this URL lead to the company's verified primary domain or an authorized ATS?"],
      suggestedAction: "Inspect redirection hops and destination domain registration authenticity.",
    });
  }

  // Claim 6: Shortlisting / Selection (OBSERVED in message)
  if (isShortlistedClaim) {
    claims.push({
      id: "claim-offer-shortlist",
      category: "shortlisting_claim",
      claimTitle: "Unsolicited Shortlisting Claim",
      extractedValue: "Candidate shortlisted without prior application",
      status: "OBSERVED",
      observationTime: now,
      explanation: "The message claims the candidate was shortlisted or selected, often before any formal application or preliminary interview.",
      unresolvedQuestions: ["Did the candidate explicitly submit a verifiable application for this specific role?"],
      suggestedAction: "Verify previous application history in your candidate portal.",
    });
  }

  // Claim 7: Urgency Window (OBSERVED in message)
  if (urgencyText) {
    claims.push({
      id: "claim-offer-urgency",
      category: "deadline_urgency",
      claimTitle: "Artificial Urgency Window",
      extractedValue: urgencyText,
      status: "OBSERVED",
      observationTime: now,
      explanation: `Artificial time pressure applied: "${urgencyText}". High-pressure deadlines are frequently used to induce hasty payments.`,
      unresolvedQuestions: ["Is this deadline authentic or an artificial pressure tactic?"],
      suggestedAction: "Legitimate corporate recruiters provide reasonable scheduling windows and never demand instant fee transfer.",
    });
  }

  // Claim 8: No Interview Selection Process (OBSERVED in message)
  if (noInterviewClaim) {
    claims.push({
      id: "claim-offer-no-interview",
      category: "interview_process",
      claimTitle: "Selection Without Interview Assessment",
      extractedValue: recruitmentAnalysis.process.quotedText || "No interview required",
      status: "OBSERVED",
      observationTime: now,
      explanation: "The communication asserts candidate selection without any formal technical or behavioral interview.",
      unresolvedQuestions: ["Does this employer ever hire candidates without an interview?"],
      suggestedAction: "Independent confirmation through official company careers portal.",
    });
  }

  // Claim 9: Offer Letter Paywall (OBSERVED in message)
  if (recruitmentAnalysis.process.offerLetterPaywall || recruitmentAnalysis.process.employeeIdPaywall) {
    claims.push({
      id: "claim-offer-paywall",
      category: "document_request",
      claimTitle: "Offer Letter / Employee ID Conditioned on Payment",
      extractedValue: "Offer letter and employee ID generated only after payment confirmation",
      status: "OBSERVED",
      observationTime: now,
      explanation: "The offer explicitly withholds the offer letter and employee ID until an upfront fee is transferred.",
      unresolvedQuestions: ["Do legitimate companies condition basic hiring paperwork on candidate payment?"],
      suggestedAction: "DO NOT PAY. Legitimate employers generate offer letters and IDs without candidate fees.",
    });
  }

  return {
    companyName,
    roleTitle,
    recruiterName,
    recruiterDesignation,
    senderEmail,
    senderPhone,
    paymentAmount,
    paymentCurrency,
    paymentReason,
    paymentChannel,
    applicationUrl,
    urgencyText,
    isShortlistedClaim,
    noInterviewClaim,
    recruitmentAnalysis,
    claims,
  };
}
