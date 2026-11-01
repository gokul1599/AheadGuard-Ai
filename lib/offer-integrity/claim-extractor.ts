import { OfferIntegrityInput, OfferClaimItem, CanonicalOfferExtraction } from "./types";
import { BRAND_DOMAIN_REGISTRY } from "../policy";
import {
  analyzeRecruitmentBehavior,
  RecruitmentBehaviorAnalysis,
} from "../recruitment-intelligence";

export interface ExtractedOfferData {
  companyName?: string;
  roleTitle?: string;
  duration?: string;
  workMode?: string;
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
  canonicalExtraction?: CanonicalOfferExtraction;
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

    // Pattern 1: Explicit Key-Value line: "Company: Nexora AI Labs Pvt. Ltd." or "Employer: Nexora AI Labs"
    if (!companyName) {
      const compKV = text.match(/(?:Company|Employer|Organization|Firm):\s*([^\n\r,]+)/i);
      if (compKV && compKV[1]) {
        companyName = compKV[1].trim();
      }
    }

    // Pattern 2: "selected for ... at [Company Name]" or "internship at [Company Name]"
    if (!companyName) {
      const selectedAtMatch = text.match(/(?:selected\s+for|internship\s+at|role\s+at|position\s+at)\s+(?:the\s+)?(?:[A-Za-z0-9&.\s]{2,40}?\s+at\s+)?([A-Z][A-Za-z0-9&.\s]{2,40}?)(?:\.|\n|\r|!|,|$)/i);
      if (selectedAtMatch && selectedAtMatch[1]) {
        const candidate = selectedAtMatch[1].trim();
        if (!/^(the|our|this|a|an)$/i.test(candidate)) {
          companyName = candidate;
        }
      }
    }

    // Pattern 3: Heuristic company matching if still missing
    if (!companyName) {
      const compMatch = text.match(/(?:at|with|from|joining)\s+([A-Z][A-Za-z0-9&.\s]{2,35}?)(?:\s+(?:team|careers|department|technologies|corporation|inc|ltd|limited|solutions|pvt\.?\s*ltd\.?|labs|\.|\,))/i);
      if (compMatch && compMatch[1]) {
        companyName = compMatch[1].trim();
      }
    }

    // Pattern 4: Domain match from submitted URLs
    if (!companyName && (input.vacancyUrl || input.applicationUrl)) {
      const urlToParse = input.vacancyUrl || input.applicationUrl;
      try {
        const parsed = new URL(urlToParse!);
        const host = parsed.hostname.toLowerCase();
        if (host.includes("amazon.")) {
          companyName = "Amazon";
        } else if (host.includes("google.")) {
          companyName = "Google";
        } else if (host.includes("microsoft.")) {
          companyName = "Microsoft";
        } else if (host.includes("meta.")) {
          companyName = "Meta";
        }
      } catch {}
    }
  }

  // 2. Role / Internship Title Identification
  let roleTitle = input.claimedRole?.trim();
  if (!roleTitle) {
    // Pattern 1: Key-Value: "Position: AI & Machine Learning Intern" or "Role: SDE Intern"
    const posKV = text.match(/(?:Position|Role|Job\s+Title|Title):\s*([^\n\r]+)/i);
    if (posKV && posKV[1]) {
      roleTitle = posKV[1].trim();
    }

    // Pattern 2: Subject line: "Subject: Congratulations! You Are Selected for the AI & Machine Learning Internship"
    if (!roleTitle) {
      const subjMatch = text.match(/Subject:.*?(?:Selected\s+for|for)\s+(?:the\s+)?([A-Za-z0-9&/\s-]{3,50}?\s+Intern(?:ship)?)/i);
      if (subjMatch && subjMatch[1]) {
        roleTitle = subjMatch[1].trim();
      }
    }

    // Pattern 3: URL slug from vacancyUrl or applicationUrl
    if (!roleTitle && (input.vacancyUrl || input.applicationUrl)) {
      const rawUrl = input.vacancyUrl || input.applicationUrl;
      const slugMatch = rawUrl?.match(/\/jobs\/\d+\/([a-z0-9-]+)/i);
      if (slugMatch && slugMatch[1]) {
        roleTitle = slugMatch[1]
          .split("-")
          .map((word) => {
            if (/^(sde|ai|ml|hr|qa|ui|ux|api)$/i.test(word)) return word.toUpperCase();
            if (/^(i|ii|iii|iv)$/i.test(word)) return word.toUpperCase();
            return word.charAt(0).toUpperCase() + word.slice(1);
          })
          .join(" ");
      }
    }

    // Pattern 4: Role patterns from message text
    if (!roleTitle) {
      const rolePatterns = [
        /(?:selected\s+for\s+(?:the\s+)?([A-Za-z0-9&/\s-]{3,40}?\s+Intern(?:ship)?))/i,
        /(?:internship\s+in\s+our\s+([A-Za-z\s]+?)\s+department)/i,
        /(?:role\s+of\s+([A-Za-z\s]+?\s+intern(?:ship)?))/i,
        /(?:position\s+of\s+([A-Za-z\s]+?\s+intern(?:ship)?))/i,
        /([A-Z][A-Za-z0-9&/\s-]{2,30}?\s+Intern(?:ship)?)/,
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
    }

    if (!roleTitle && /internship/i.test(text)) {
      roleTitle = "Internship Position";
    }
  }

  // 2b. Duration and Work Arrangement Identification
  const durationMatch = text.match(/(?:Duration|Period):\s*([^\n\r]+)/i) || text.match(/\b(\d+\s+(?:months?|weeks?))\b/i);
  const duration = durationMatch ? durationMatch[1].trim() : undefined;

  const workModeMatch = text.match(/(?:Work\s+Mode|Work\s+Arrangement|Location):\s*([^\n\r]+)/i) || text.match(/\b(100%\s*Remote|Remote|Hybrid|On-site)\b/i);
  const workMode = workModeMatch ? workModeMatch[1].trim() : undefined;

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

  let recruiterDesignation = input.recruiterDesignation?.trim() || recruitmentAnalysis.recruiter.designation;
  if (!recruiterDesignation) {
    const desigMatch = text.match(/(Senior\s+HR\s+Recruiter|Campus\s+Recruiter|HR\s+Recruiter|HR\s+Manager|Talent\s+Acquisition(?:\s+Specialist)?|Technical\s+Recruiter|Hiring\s+Manager|People\s+Operations|Recruitment\s+Coordinator)/i);
    if (desigMatch && desigMatch[1]) {
      recruiterDesignation = desigMatch[1].trim();
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
  if (paymentAmount || recruitmentAnalysis.fee.detected) {
    const formattedFee = paymentAmount
      ? `${paymentCurrency} ${paymentAmount}`
      : "Mandatory fee demanded (amount not disclosed in communication)";
    claims.push({
      id: "claim-offer-payment",
      category: "payment_requirement",
      claimTitle: "Mandatory Recruitment / Registration Fee",
      extractedValue: `${formattedFee}${paymentReason ? ` (${paymentReason})` : ""}`,
      status: "OBSERVED",
      observationTime: now,
      explanation: paymentAmount
        ? `The offer demands payment of ${formattedFee} prior to interview slot reservation or candidacy onboarding.`
        : `The offer explicitly conditions progression or offer letter issuance on payment of a mandatory recruitment fee, without disclosing the exact numerical amount.`,
      unresolvedQuestions: ["Does the employer's published hiring policy allow applicant fees or slot reservation payments?"],
      suggestedAction: "Check the employer's published candidate guidance and anti-fraud hiring policy. DO NOT PAY.",
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

  // Claim 10: Refundable Fee Guarantee Claim (OBSERVED in message)
  if (recruitmentAnalysis.fee.refundabilityClaimed) {
    claims.push({
      id: "claim-offer-refund",
      category: "payment_requirement",
      claimTitle: "Refundable Fee Guarantee Claim",
      extractedValue: "Fee promised to be refunded with first month's stipend",
      status: "OBSERVED",
      observationTime: now,
      explanation: "The offer claims upfront fees are refundable with future compensation. Refund promises are a hallmark tactic in advance-fee employment fraud.",
      unresolvedQuestions: ["Has any regulatory or corporate body ever validated fee refunds from this sender?"],
      suggestedAction: "DO NOT PAY. Fraudulent fee demands universally promise refunds that never materialize.",
    });
  }

  // Claim 11: Payment Target / UPI ID (OBSERVED in message)
  if (recruitmentAnalysis.fee.upiId) {
    claims.push({
      id: "claim-offer-upi-target",
      category: "payment_requirement",
      claimTitle: "Payment Recipient UPI Handle",
      extractedValue: recruitmentAnalysis.fee.upiId,
      status: "OBSERVED",
      observationTime: now,
      explanation: `Payment directed to individual/third-party UPI handle: ${recruitmentAnalysis.fee.upiId}.`,
      unresolvedQuestions: ["Is this UPI VPA registered to a verified corporate bank account?"],
      suggestedAction: "Never transfer recruitment fees to personal VPA handles.",
    });
  }

  // Claim 12: Stated Monthly Stipend / Compensation (OBSERVED in message)
  if (recruitmentAnalysis.process.stipendAmount) {
    claims.push({
      id: "claim-offer-compensation",
      category: "vacancy_existence",
      claimTitle: "Claimed Monthly Stipend",
      extractedValue: recruitmentAnalysis.process.stipendAmount,
      status: "OBSERVED",
      observationTime: now,
      explanation: `Stated stipend of ${recruitmentAnalysis.process.stipendAmount} claimed in submitted communication.`,
      unresolvedQuestions: ["Is this compensation figure corroborated on official enterprise listings?"],
      suggestedAction: "Cross-reference against authentic corporate salary benchmarks.",
    });
  }

  // 9. Assemble Canonical Extraction Object
  const canonicalExtraction: CanonicalOfferExtraction = {
    employer: {
      name: companyName || "Could not extract this field — manual review required",
      status: companyName ? "UNVERIFIED" : "NOT_CHECKED",
      rawExtracted: companyName,
    },
    job: {
      title: roleTitle || "Could not extract this field — manual review required",
      duration,
      workMode,
      referenceId: (input.vacancyUrl || applicationUrl)?.match(/\/jobs\/(\d+)/i)?.[1],
      status: roleTitle ? "UNVERIFIED" : "NOT_CHECKED",
    },
    compensation: {
      disclosedInMessage: Boolean(recruitmentAnalysis.process.stipendAmount),
      amount: recruitmentAnalysis.process.stipendNumeric,
      amountString: recruitmentAnalysis.process.stipendAmount,
      currency: recruitmentAnalysis.process.stipendCurrency || "INR",
      period: "MONTHLY",
      status: recruitmentAnalysis.process.stipendAmount ? "UNVERIFIED" : "NOT_DISCLOSED_IN_LISTING",
    },
    recruiter: {
      name: recruiterName,
      designation: recruiterDesignation,
      channel: recruitmentAnalysis.recruiter.channel,
      handle: recruitmentAnalysis.recruiter.handleOrContact,
      email: senderEmail,
      phone: senderPhone,
      affiliationStatus: "UNVERIFIED",
    },
    payment: {
      requested: Boolean(recruitmentAnalysis.fee.detected || paymentAmount),
      amount: recruitmentAnalysis.fee.numericAmount,
      amountString: paymentAmount || (recruitmentAnalysis.fee.detected ? "Undisclosed" : undefined),
      currency: paymentCurrency,
      method: paymentChannel || recruitmentAnalysis.fee.paymentMethod,
      upiId: recruitmentAnalysis.fee.upiId,
      mandatory: recruitmentAnalysis.fee.mandatory,
      refundableClaimed: recruitmentAnalysis.fee.refundabilityClaimed,
      deadline: urgencyText,
      statedReason: paymentReason || recruitmentAnalysis.fee.reason,
    },
    selection: {
      interviewRequired: !noInterviewClaim,
      paymentRequiredForOfferLetter: recruitmentAnalysis.process.offerLetterPaywall,
      shortlistedClaim: isShortlistedClaim,
    },
    application: {
      url: applicationUrl,
      domainClassification: applicationUrl ? (applicationUrl.includes(".example") ? "SYNTHETIC_RESERVED" : "UNVERIFIED_THIRD_PARTY") : undefined,
    },
  };

  return {
    companyName,
    roleTitle,
    duration,
    workMode,
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
    canonicalExtraction,
  };
}
