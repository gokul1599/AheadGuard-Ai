// Types for dedicated Recruitment Behavior Intelligence

export interface RecruitmentFeeDetection {
  detected: boolean;
  amount?: string;
  numericAmount?: number;
  currency?: string;
  category:
    | "REGISTRATION_AND_ONBOARDING"
    | "INTERVIEW_SLOT_RESERVATION"
    | "SECURITY_DEPOSIT"
    | "TRAINING_AND_COURSE"
    | "EQUIPMENT_AND_LAPTOP"
    | "DOCUMENT_VERIFICATION"
    | "OFFER_LETTER_RELEASE"
    | "UNSPECIFIED_RECRUITMENT_FEE";
  mandatory: boolean;
  refundabilityClaimed: boolean;
  deadline?: string;
  paymentMethod?: string;
  upiId?: string;
  recipient?: string;
  reason?: string;
  quotedText: string;
  confidence: number;
  evidenceSource: "SUBMITTED_MESSAGE";
  classification: "OBSERVED";
}

export interface RecruitmentUrgencyDetection {
  detected: boolean;
  deadlineText?: string;
  urgencyWindow?: string;
  coerciveTactic?: string;
  quotedText: string;
  confidence: number;
  evidenceSource: "SUBMITTED_MESSAGE";
  classification: "OBSERVED";
}

export interface RecruitmentProcessAnomalies {
  noInterviewRequired: boolean;
  guaranteedSelection: boolean;
  offerLetterPaywall: boolean;
  employeeIdPaywall: boolean;
  stipendUnverifiedLure: boolean;
  stipendAmount?: string;
  stipendNumeric?: number;
  stipendCurrency?: string;
  quotedText?: string;
  evidenceSource: "SUBMITTED_MESSAGE";
  classification: "OBSERVED";
}

export interface RecruiterIdentityAnalysis {
  name?: string;
  designation?: string;
  channel?: "Telegram" | "WhatsApp" | "Email" | "SMS" | "Direct P2P" | "Official Corporate Portal" | "Other";
  handleOrContact?: string;
  emailDomain?: string;
  isPersonalMessagingChannel: boolean;
  affiliationStatus: "OBSERVED" | "VERIFIED" | "UNVERIFIED" | "CONTRADICTED";
  explanation: string;
}

export interface RecruitmentRiskIndicatorItem {
  id: string;
  indicator: string;
  finding: "Detected" | "Observed" | "Unverified" | "Contradicted" | "Not Detected";
  evidence: string;
  severity: "low" | "medium" | "high" | "severe";
  deduplicationKey: string;
}

export interface RecruitmentBehaviorAnalysis {
  fee: RecruitmentFeeDetection;
  urgency: RecruitmentUrgencyDetection;
  process: RecruitmentProcessAnomalies;
  recruiter: RecruiterIdentityAnalysis;
  isOptionalTrainingNotice: boolean;
  indicators: RecruitmentRiskIndicatorItem[];
}

/**
 * Normalizes currency symbols to ISO codes.
 */
export function normalizeCurrency(raw: string): string {
  const clean = raw.trim().toUpperCase();
  if (clean === "₹" || clean === "RS." || clean === "RS" || clean === "INR") return "INR";
  if (clean === "$" || clean === "USD") return "USD";
  if (clean === "€" || clean === "EUR") return "EUR";
  if (clean === "£" || clean === "GBP") return "GBP";
  return clean || "INR";
}

/**
 * Primary Recruitment Behavior Intelligence Analyzer.
 * Extracts structured behavioral evidence from user-submitted text and fields
 * independently of whether external employer registries resolve.
 */
export function analyzeRecruitmentBehavior(params: {
  text: string;
  claimedCompany?: string;
  claimedRole?: string;
  recruiterName?: string;
  recruiterDesignation?: string;
  senderEmail?: string;
  senderPhone?: string;
  paymentAmount?: string;
  paymentReason?: string;
  applicationUrl?: string;
  vacancyUrl?: string;
}): RecruitmentBehaviorAnalysis {
  const text = (params.text || "").trim();

  // 1. Check for Optional Non-Fee Training (Test 6 Requirement)
  // E.g. "We offer optional paid certification workshops through Coursera. Selection is completely free."
  const isOptionalTrainingNotice = checkIsOptionalTrainingNotice(text);

  // 2. Fee Detection
  const fee = extractRecruitmentFee(text, params, isOptionalTrainingNotice);

  // 3. Urgency and Coercion Detection
  const urgency = extractRecruitmentUrgency(text);

  // 4. Recruitment Process Anomalies (No interview, paywall for offer letter/employee ID)
  const process = extractProcessAnomalies(text);

  // 5. Recruiter Channel & Identity
  const recruiter = extractRecruiterChannel(text, params);

  // 6. Synthesize Unified Structured Risk Indicators
  const indicators: RecruitmentRiskIndicatorItem[] = [];

  // Upfront Recruitment Fee Indicator
  if (fee.detected) {
    const feeStr = fee.amount ? `${fee.currency || "INR"} ${fee.amount}` : "Upfront Fee Demanded";
    const details = [
      feeStr,
      fee.refundabilityClaimed ? "claimed refundable" : undefined,
      fee.paymentMethod ? `via ${fee.paymentMethod}` : undefined,
    ].filter(Boolean).join(" ");

    indicators.push({
      id: "rec-ind-fee",
      indicator: "Upfront recruitment payment",
      finding: "Detected",
      evidence: details,
      severity: "severe",
      deduplicationKey: "fee_demand",
    });
  }

  // Payment Urgency Indicator
  if (urgency.detected) {
    indicators.push({
      id: "rec-ind-urgency",
      indicator: "Payment urgency",
      finding: "Detected",
      evidence: urgency.deadlineText || urgency.quotedText || "Strict payment deadline",
      severity: "high",
      deduplicationKey: "payment_urgency",
    });
  }

  // Selection Without Interview
  if (process.noInterviewRequired) {
    indicators.push({
      id: "rec-ind-no-interview",
      indicator: "Selection without interview",
      finding: "Observed",
      evidence: process.quotedText || "Candidate selected without formal interview assessment",
      severity: "high",
      deduplicationKey: "no_interview_process",
    });
  }

  // Offer Letter / Employee ID Paywall
  if (process.offerLetterPaywall || process.employeeIdPaywall) {
    indicators.push({
      id: "rec-ind-doc-paywall",
      indicator: "Credentials/Offer released only after payment",
      finding: "Observed",
      evidence: "Offer letter or Employee ID generation conditioned upon fee transfer",
      severity: "severe",
      deduplicationKey: "doc_paywall",
    });
  }

  // Recruiter Messaging Channel
  if (recruiter.isPersonalMessagingChannel && recruiter.channel) {
    indicators.push({
      id: "rec-ind-recruiter-channel",
      indicator: "Recruiter identity",
      finding: "Unverified",
      evidence: `${recruiter.channel} handle: ${recruiter.handleOrContact || "Private messaging contact"}`,
      severity: "medium",
      deduplicationKey: "recruiter_channel",
    });
  }

  // Destination Domain Namespace Check (.example / reserved)
  const destUrl = params.applicationUrl || params.vacancyUrl || "";
  if (destUrl) {
    try {
      const parsedHost = new URL(destUrl.startsWith("http") ? destUrl : `https://${destUrl}`).hostname.toLowerCase();
      if (parsedHost.endsWith(".example") || parsedHost.endsWith(".test") || parsedHost.endsWith(".invalid") || parsedHost.endsWith(".localhost")) {
        indicators.push({
          id: "rec-ind-reserved-domain",
          indicator: "Destination domain",
          finding: "Observed",
          evidence: `Reserved example namespace (${parsedHost}) cannot serve as an operational enterprise careers portal (RFC 2606)`,
          severity: "high",
          deduplicationKey: "reserved_example_namespace",
        });
      }
    } catch {
      // ignore url parse
    }
  }

  return {
    fee,
    urgency,
    process,
    recruiter,
    isOptionalTrainingNotice,
    indicators,
  };
}

/**
 * Checks whether text describes optional, unrelated training rather than a mandatory recruitment fee.
 */
function checkIsOptionalTrainingNotice(text: string): boolean {
  if (!text) return false;
  const isOptionalMention =
    /(?:optional|voluntary|elective|not\s+required|not\s+mandatory|selection\s+is\s+(?:100%\s+)?free|no\s+(?:mandatory\s+)?fee\s+for\s+employment)\b/i.test(text);
  const isExternalUpsell =
    /(?:third-party|coursera|udemy|external\s+certification|recommended\s+reading|further\s+studies)\b/i.test(text);
  const isFreeHiringExplicit =
    /(?:hiring\s+is\s+free|recruitment\s+is\s+free|never\s+charge\s+candidates|we\s+do\s+not\s+charge)\b/i.test(text);

  return (isOptionalMention || isFreeHiringExplicit || isExternalUpsell) && !/(?:must\s+pay|required\s+to\s+pay|mandatory\s+fee|confirm\s+your\s+selection\s+by\s+paying)\b/i.test(text);
}

/**
 * Comprehensive fee extractor.
 */
function extractRecruitmentFee(
  text: string,
  params: {
    paymentAmount?: string;
    paymentReason?: string;
  },
  isOptionalTraining: boolean
): RecruitmentFeeDetection {
  if (isOptionalTraining) {
    return {
      detected: false,
      mandatory: false,
      refundabilityClaimed: false,
      quotedText: "",
      confidence: 0,
      evidenceSource: "SUBMITTED_MESSAGE",
      classification: "OBSERVED",
      category: "UNSPECIFIED_RECRUITMENT_FEE",
    };
  }

  // 1. Detect Amount and Currency
  let amountStr = params.paymentAmount?.trim();
  let currency = "INR";
  let quotedText = "";
  let refundabilityClaimed = false;
  let deadline: string | undefined;
  let paymentMethod: string | undefined;
  let feeCategory: RecruitmentFeeDetection["category"] = "REGISTRATION_AND_ONBOARDING";

  // Check refundability
  if (/(?:refundable|refunded\s+after|refunded\s+with|returned\s+after|reimbursable)/i.test(text)) {
    refundabilityClaimed = true;
  }

  // Check UPI ID
  const upiIdMatch =
    text.match(/(?:UPI\s*(?:ID)?|VPA|pay\s+to|pay\s+via|UPI):\s*([a-zA-Z0-9_.-]+@[a-zA-Z0-9_]+)/i) ||
    text.match(/\b([a-zA-Z0-9_.-]+@(upi|okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|axl|barodampay|icici|hdfcbank))\b/i);
  const upiId = upiIdMatch ? upiIdMatch[1].trim() : undefined;

  // Check payment method
  const payMethodKV = text.match(/(?:Payment\s*Method|Pay\s*via|Payment\s*Mode):\s*([^\n\r]+)/i);
  if (payMethodKV) {
    paymentMethod = payMethodKV[1].trim();
  } else if (upiId || /UPI|GPay|GooglePay|PhonePe|Paytm|BHIM/i.test(text)) {
    paymentMethod = "UPI";
  } else if (/QR\s*code/i.test(text)) {
    paymentMethod = "QR Code";
  } else if (/bank\s+transfer|NEFT|IMPS|RTGS/i.test(text)) {
    paymentMethod = "Bank Transfer";
  } else if (/crypto|bitcoin|usdt/i.test(text)) {
    paymentMethod = "Cryptocurrency";
  }

  // Pattern 0: Structured Key-Value Line: "Amount: ₹999", "Fee: ₹999", "Amount: 999"
  if (!amountStr) {
    const feeRegexKV = /(?:Amount|Registration\s+Fee|Fee|Payment|Deposit|Charges?):\s*(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)?\s*([0-9,]+(?:\.[0-9]{2})?)/i;
    const matchKV = text.match(feeRegexKV);
    if (matchKV) {
      currency = normalizeCurrency(matchKV[1] || "INR");
      amountStr = matchKV[2].replace(/,/g, "");
      quotedText = matchKV[0].trim();
    }
  }

  // Pattern A: "complete a [refundable] registration and onboarding payment of ₹999"
  // Handles: complete/make/remit/paying/pay/deposit/depositing/transfer/transferring/send/submitting
  if (!amountStr) {
    const feeRegex1 =
      /(?:complete|make|remit|paying|pay|deposit|depositing|transfer|transferring|send|sending|submitting)\s+(?:a|an|the|any)?\s*(?:(?:mandatory|refundable|nominal|one-time|advance|initial)\s+)?([a-z\s/&,-]{2,40}?)\s*(?:payment|fee|fees|charge|charges|deposit|deposits|amount)s?\s+(?:of\s+)?(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)?\s*([0-9,]+(?:\.[0-9]{2})?)/i;

    const match1 = text.match(feeRegex1);
    if (match1) {
      const rawCategory = match1[1].toLowerCase();
      currency = normalizeCurrency(match1[2] || "INR");
      amountStr = match1[3].replace(/,/g, "");
      quotedText = match1[0].trim();

      if (rawCategory.includes("registration") || rawCategory.includes("onboarding")) {
        feeCategory = "REGISTRATION_AND_ONBOARDING";
      } else if (rawCategory.includes("interview") || rawCategory.includes("slot")) {
        feeCategory = "INTERVIEW_SLOT_RESERVATION";
      } else if (rawCategory.includes("security") || rawCategory.includes("equipment") || rawCategory.includes("laptop")) {
        feeCategory = "SECURITY_DEPOSIT";
      } else if (rawCategory.includes("training") || rawCategory.includes("induction")) {
        feeCategory = "TRAINING_AND_COURSE";
      } else if (rawCategory.includes("document") || rawCategory.includes("verification")) {
        feeCategory = "DOCUMENT_VERIFICATION";
      }
    }
  }

  // Pattern A2: "The ₹999 amount will be refunded" or "₹999 amount will be refunded"
  if (!amountStr) {
    const feeRegexRefund = /(?:the\s+)?(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)?\s*([0-9,]+(?:\.[0-9]{2})?)\s*(?:amount\s+)?(?:will\s+be|is)\s*(?:refunded|reimbursed|returned)/i;
    const matchRefund = text.match(feeRegexRefund);
    if (matchRefund) {
      currency = normalizeCurrency(matchRefund[1] || "INR");
      amountStr = matchRefund[2].replace(/,/g, "");
      quotedText = matchRefund[0].trim();
      refundabilityClaimed = true;
    }
  }

  // Pattern B: "[amount] [fee/deposit/charge] for [selection/onboarding/interview]"
  if (!amountStr) {
    const feeRegex2 =
      /(?:fee|charge|deposit|amount)\s+of\s+(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)?\s*([0-9,]+(?:\.[0-9]{2})?)\s*(?:(?:is\s+)?(?:required|mandatory|to\s+confirm|for\s+onboarding|for\s+registration|for\s+training))?/i;
    const match2 = text.match(feeRegex2);
    if (match2) {
      currency = normalizeCurrency(match2[1] || "INR");
      amountStr = match2[2].replace(/,/g, "");
      quotedText = match2[0].trim();
    }
  }

  // Pattern C: "Pay (₹|INR|Rs|$)[amount] to [reserve/confirm/register]"
  if (!amountStr) {
    const feeRegex3 =
      /(?:pay|paying|transfer|deposit|send)\s+(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)\s*([0-9,]+(?:\.[0-9]{2})?)\s+(?:to\s+(?:reserve|confirm|register|book|receive|get|generate))/i;
    const match3 = text.match(feeRegex3);
    if (match3) {
      currency = normalizeCurrency(match3[1] || "INR");
      amountStr = match3[2].replace(/,/g, "");
      quotedText = match3[0].trim();
    }
  }

  // Pattern D: "complete [employee] verification by paying ... fee of ₹[amount]"
  if (!amountStr) {
    const feeRegex4 =
      /(?:verification|confirmation|registration|onboarding)\s+by\s+(?:paying|transferring|depositing)\s+(?:.*?)(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)\s*([0-9,]+(?:\.[0-9]{2})?)/i;
    const match4 = text.match(feeRegex4);
    if (match4) {
      currency = normalizeCurrency(match4[1] || "INR");
      amountStr = match4[2].replace(/,/g, "");
      quotedText = match4[0].trim();
    }
  }

  // Pattern E: "Pay/Transfer (currency) (amount) [for/as ...]" (e.g. Pay ₹2,500 security deposit, Transfer INR 2,500 for training deposit)
  if (!amountStr) {
    const feeRegex5 =
      /(?:paying|pay|deposit|depositing|transfer|transferring|send|sending)\s+(?:of\s+)?(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)\s*([0-9,]+(?:\.[0-9]{2})?)/i;
    const match5 = text.match(feeRegex5);
    if (match5) {
      currency = normalizeCurrency(match5[1] || "INR");
      amountStr = match5[2].replace(/,/g, "");
      quotedText = match5[0].trim();
    }
  }

  // Pattern F: "(refundable) security/equipment/training deposit of (currency) (amount)"
  if (!amountStr) {
    const feeRegex6 =
      /(?:(?:an?|the|any|a)\s+)?(?:refundable\s+)?(?:security|caution|guarantee|equipment|laptop|training|registration|application|onboarding)\s+(?:deposit|fee|charge)s?\s+of\s+(₹|INR|Rs\.?|\$|USD|€|EUR|£|GBP)?\s*([0-9,]+(?:\.[0-9]{2})?)/i;
    const match6 = text.match(feeRegex6);
    if (match6) {
      currency = normalizeCurrency(match6[1] || "INR");
      amountStr = match6[2].replace(/,/g, "");
      quotedText = match6[0].trim();
    }
  }

  // Categorize fee accurately based on context and keywords
  if (/(?:registration|onboarding|application|processing|portal|assessment)/i.test(text)) {
    feeCategory = "REGISTRATION_AND_ONBOARDING";
  } else if (/(?:security|caution|guarantee|equipment|laptop)/i.test(text)) {
    feeCategory = "SECURITY_DEPOSIT";
  } else if (/(?:training|course|induction|orientation)/i.test(text)) {
    feeCategory = "TRAINING_AND_COURSE";
  } else if (/(?:interview|appointment|slot)\s*(?:fee|charge|reservation)/i.test(text)) {
    feeCategory = "INTERVIEW_SLOT_RESERVATION";
  } else if (/(?:document|verification|id\s*card)/i.test(text)) {
    feeCategory = "DOCUMENT_VERIFICATION";
  }

  // Ensure quotedText includes the full descriptive phrase if present
  const fullDepositPhrase = text.match(/(?:(?:an?|the|any|a)\s+)?(?:refundable\s+)?(?:security|caution|guarantee|equipment|laptop|training|registration|application|onboarding)\s+(?:deposit|fee|charge)s?(?:\s+of\s+[$₹€£0-9,.]+)?(?:\s+(?:is\s+)?(?:required|mandatory))?/i);
  if (fullDepositPhrase && (!quotedText || fullDepositPhrase[0].length > quotedText.length)) {
    quotedText = fullDepositPhrase[0].trim();
  }

  // Direct parameter fallback if amount was provided in structured input
  if (!amountStr && params.paymentAmount) {
    const cleanAmt = params.paymentAmount.replace(/[^0-9.]/g, "");
    if (cleanAmt) {
      amountStr = cleanAmt;
      quotedText = params.paymentReason || `Payment of ${amountStr} requested`;
    }
  }

  // General recruitment fee phrasing match if no numeric amount was given but payment is demanded
  const genericFeePhrase =
    /(?:pay|deposit|send|transfer)\s+(?:a\s+)?(?:mandatory\s+)?(?:registration|onboarding|interview|training|equipment|offer\s+letter)\s+(?:fee|deposit|charge)/i;
  const genericMatch = text.match(genericFeePhrase);

  const detected = Boolean(amountStr || genericMatch);
  if (!quotedText && genericMatch) {
    quotedText = genericMatch[0];
  }

  // Extract deadline associated with payment
  const deadlineMatch = text.match(/(?:payment\s+must\s+be\s+completed|pay|transfer)\s+(?:within\s+\d+\s+hours?|before\s+[0-9:]+|by\s+[a-z0-9\s]+)/i) ||
    text.match(/within\s+(\d+\s+hours?)/i);
  if (deadlineMatch) {
    deadline = deadlineMatch[0].trim();
  }

  const numericAmount = amountStr ? parseFloat(amountStr) : undefined;

  return {
    detected,
    amount: amountStr,
    numericAmount,
    currency: detected ? currency : undefined,
    category: feeCategory,
    mandatory: detected,
    refundabilityClaimed,
    deadline,
    paymentMethod,
    upiId,
    reason: params.paymentReason || "Registration and onboarding fee",
    quotedText,
    confidence: detected ? 1.0 : 0,
    evidenceSource: "SUBMITTED_MESSAGE",
    classification: "OBSERVED",
  };
}

/**
 * Extracts urgency deadlines and high-pressure coercion phrasing.
 */
function extractRecruitmentUrgency(text: string): RecruitmentUrgencyDetection {
  if (!text) {
    return {
      detected: false,
      quotedText: "",
      confidence: 0,
      evidenceSource: "SUBMITTED_MESSAGE",
      classification: "OBSERVED",
    };
  }

  const urgencyPatterns = [
    /(?:within\s+\d+\s+hours?)/i,
    /(?:payment\s+must\s+be\s+completed\s+within\s+\d+\s+hours?)/i,
    /(?:before\s+\d+:\d+\s*(?:am|pm)?)/i,
    /(?:expires\s+(?:today|in\s+\d+\s+hours?|soon))/i,
    /(?:only\s+\d+\s+slots?\s+remaining)/i,
    /(?:immediate\s+confirmation\s+required)/i,
    /(?:confirm\s+immediately|pay\s+now\s+or\s+lose)/i,
    /(?:failing\s+which\s+your\s+candidacy\s+will\s+be\s+cancelled)/i,
    /(?:offer\s+will\s+be\s+revoked)/i,
  ];

  for (const pat of urgencyPatterns) {
    const match = text.match(pat);
    if (match) {
      return {
        detected: true,
        deadlineText: match[0].trim(),
        urgencyWindow: match[0].trim(),
        coerciveTactic: "Artificial deadline applied to force hasty payment without independent verification",
        quotedText: match[0].trim(),
        confidence: 0.95,
        evidenceSource: "SUBMITTED_MESSAGE",
        classification: "OBSERVED",
      };
    }
  }

  return {
    detected: false,
    quotedText: "",
    confidence: 0,
    evidenceSource: "SUBMITTED_MESSAGE",
    classification: "OBSERVED",
  };
}

/**
 * Extracts process anomalies such as "no interview required", guaranteed selection,
 * or conditioning offer letter generation on payment.
 */
function extractProcessAnomalies(
  text: string
): RecruitmentProcessAnomalies {
  const noInterview =
    /(?:no\s+interview(?:\s+is)?\s+required|selected\s+without\s+interview|direct\s+selection\s+without\s+interview|without\s+any\s+interview|skip\s+interview)/i.test(text);

  const guaranteedSelection =
    /(?:congratulations!\s*you\s+have\s+been\s+shortlisted|you\s+are\s+selected\s+for|direct\s+placement|guaranteed\s+internship|100%\s+selection)/i.test(text);

  const offerLetterPaywall =
    /(?:only\s+candidates\s+who\s+complete\s+payment\s+will\s+receive\s+(?:their\s+)?offer\s+letter|after\s+payment\s+confirmation,\s*your\s+digital\s+offer\s+letter|offer\s+letter\s+will\s+be\s+generated\s+after\s+payment|pay\s+to\s+receive\s+offer\s+letter|offer\s+letter\s+generation\s+conditioned\s+on\s+payment|digital\s+offer\s+letter\s+generation)/i.test(text);

  const employeeIdPaywall =
    /(?:employee\s+id\s+will\s+be\s+generated|release\s+(?:your\s+)?employee\s+id|id\s+card\s+after\s+payment)/i.test(text);

  // Stated compensation / stipend extraction
  let stipendUnverifiedLure = false;
  let stipendAmount: string | undefined;
  let stipendNumeric: number | undefined;
  let stipendCurrency: string | undefined;

  const stipendMatch =
    text.match(/(?:Monthly\s+Stipend|Stipend|Salary|Compensation):\s*(₹|INR|Rs\.?|\$|USD)?\s*([0-9,]+(?:\s*(?:per\s+month|\/mo))?)/i) ||
    text.match(/(?:stipend|salary|compensation)\s+(?:of\s+)?(₹|INR|Rs\.?|\$|USD)\s*([0-9,]+(?:\s*per\s+month|\/mo)?)/i);

  if (stipendMatch) {
    stipendUnverifiedLure = true;
    stipendCurrency = normalizeCurrency(stipendMatch[1] || "INR");
    const rawVal = stipendMatch[2].replace(/,/g, "").trim();
    stipendNumeric = parseFloat(rawVal);
    stipendAmount = `${stipendMatch[1] || "₹"}${stipendMatch[2]}`.trim();
  }

  let quotedText: string | undefined;
  if (noInterview) {
    const m = text.match(/(?:no\s+interview(?:\s+is)?\s+required[a-z\s]*|selected\s+without\s+interview[a-z\s]*)/i);
    quotedText = m ? m[0].trim() : "No interview is required for this position";
  }

  return {
    noInterviewRequired: noInterview,
    guaranteedSelection,
    offerLetterPaywall,
    employeeIdPaywall,
    stipendUnverifiedLure,
    stipendAmount,
    stipendNumeric,
    stipendCurrency,
    quotedText,
    evidenceSource: "SUBMITTED_MESSAGE",
    classification: "OBSERVED",
  };
}

/**
 * Extracts recruiter channel, Telegram handles, personal webmail, and affiliation signals.
 */
function extractRecruiterChannel(
  text: string,
  params: {
    recruiterName?: string;
    recruiterDesignation?: string;
    senderEmail?: string;
    senderPhone?: string;
    claimedCompany?: string;
  }
): RecruiterIdentityAnalysis {
  let name = params.recruiterName?.trim();
  let designation = params.recruiterDesignation?.trim();

  // If recruiter name not provided, extract from message blocks (avoiding matching newlines in name)
  if (!name) {
    const blockMatch =
      text.match(/(?:Recruitment\s+Coordinator|Recruiter\s+Contact|Recruiter\s+Details|HR\s+Contact|Point\s+of\s+Contact):\s*\r?\n\s*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)+)/i) ||
      text.match(/(?:Recruiter\s+Name|Recruiter|HR\s+Name|Contact\s+Person):\s*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)+)/i);
    if (blockMatch && blockMatch[1]) {
      name = blockMatch[1].trim();
    }
  }

  // If designation not provided, check the line immediately following recruiter name
  if (!designation && name) {
    const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const nextLineMatch = text.match(new RegExp(`${escapedName}\\s*\\r?\\n\\s*([^\\r\\n]+)`, "i"));
    if (nextLineMatch && nextLineMatch[1]) {
      const line = nextLineMatch[1].trim();
      if (/recruiter|talent|hr|coordinator|manager|specialist|officer/i.test(line)) {
        designation = line;
      }
    }
  }

  // Fallback designation regex
  if (!designation) {
    const desigMatch = text.match(/(Senior\s+HR\s+Recruiter|Campus\s+Recruiter|HR\s+Recruiter|HR\s+Manager|Talent\s+Acquisition(?:\s+Specialist)?|Technical\s+Recruiter|Hiring\s+Manager|People\s+Operations|Recruitment\s+Coordinator)/i);
    if (desigMatch && desigMatch[1]) {
      designation = desigMatch[1].trim();
    }
  }

  let channel: RecruiterIdentityAnalysis["channel"] = "Other";
  let handleOrContact: string | undefined;
  let isPersonalMessaging = false;
  let emailDomain: string | undefined;

  // 1. Check for Telegram handle: Telegram: @username, @username (Telegram), t.me/username
  const tgMatch =
    text.match(/(?:Telegram|TG):\s*@?([a-zA-Z0-9_]{3,32})/i) ||
    (params.recruiterName && params.recruiterName.match(/@([a-zA-Z0-9_]{3,32})/)) ||
    text.match(/@([a-zA-Z0-9_]{3,32})\s*(?:\(Telegram\)|\s+on\s+Telegram)/i) ||
    text.match(/t\.me\/([a-zA-Z0-9_]{3,32})/i) ||
    (params.recruiterName && /Telegram/i.test(params.recruiterName) ? params.recruiterName.match(/@([a-zA-Z0-9_]+)/) : null);

  if (tgMatch) {
    channel = "Telegram";
    handleOrContact = `@${tgMatch[1]}`;
    isPersonalMessaging = true;
    if (!name && params.recruiterName) {
      name = params.recruiterName.split("—")[0].split("-")[0].trim();
    }
  }

  // 2. Check for WhatsApp
  if (!handleOrContact) {
    const waMatch = text.match(/(?:WhatsApp|WA)\s*(?:on|to|at)?\s*(\+?[0-9\s-]{10,15})/i);
    if (waMatch) {
      channel = "WhatsApp";
      handleOrContact = waMatch[1].trim();
      isPersonalMessaging = true;
    }
  }

  // 3. Sender Email domain check
  const email = params.senderEmail || (text.match(/([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/)?.[1]);
  if (email) {
    emailDomain = email.split("@")[1]?.toLowerCase();
    const isFreeMail = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "icloud.com"].includes(emailDomain || "");
    if (isFreeMail) {
      isPersonalMessaging = true;
      if (channel === "Other") channel = "Email";
      if (!handleOrContact) handleOrContact = email;
    }
  }

  const explanation = isPersonalMessaging
    ? `Recruiter utilizes an unverified direct messaging channel (${channel}: ${handleOrContact || "personal handle"}). Legitimate corporate recruiters communicate via authenticated corporate domains, not anonymous consumer messaging accounts.`
    : "Recruiter identity and employer affiliation could not be independently corroborated against verified enterprise directories.";

  return {
    name,
    designation: designation || "Recruitment Coordinator",
    channel,
    handleOrContact,
    emailDomain,
    isPersonalMessagingChannel: isPersonalMessaging,
    affiliationStatus: "UNVERIFIED",
    explanation,
  };
}
