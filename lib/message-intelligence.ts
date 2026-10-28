import {
  ClaimRecord,
  PaymentRiskItem,
  RecruitmentFeeWarning,
  SensitiveDataRequestItem,
} from "./types";

export interface ExtractedMessageData {
  originalText: string;
  redactedText: string;
  extractedUrls: string[];
  singleExtractedUrl?: string;
  claimedOrganization?: string;
  claimedJobRole?: string;
  claimedCompensation?: string;
  recruitmentFeeWarning?: RecruitmentFeeWarning;
  paymentRisks: PaymentRiskItem[];
  sensitiveDataRequests: SensitiveDataRequestItem[];
  claims: ClaimRecord[];
  appliedRedactions: string[];
}

/**
 * Extracts and normalizes all URLs present in a text string.
 */
export function extractUrlsFromText(text: string): string[] {
  if (!text || typeof text !== "string") return [];

  // Regex matching full URLs (http/https) and standalone domain-like URLs (www. or bare known domains)
  const urlRegex = /(?:https?:\/\/|www\.)[^\s"'<>\(\)]+/gi;
  const matches = text.match(urlRegex) || [];

  const seen = new Set<string>();
  const normalizedUrls: string[] = [];

  for (const raw of matches) {
    let clean = raw.trim().replace(/[.,;:!?]+$/, ""); // strip trailing punctuation
    // Strip trailing closing brackets or parentheses if not opened within the URL string
    while (clean.endsWith(")") && (clean.match(/\(/g) || []).length < (clean.match(/\)/g) || []).length) {
      clean = clean.slice(0, -1);
    }
    while (clean.endsWith("]") && (clean.match(/\[/g) || []).length < (clean.match(/\]/g) || []).length) {
      clean = clean.slice(0, -1);
    }
    clean = clean.replace(/[.,;:!?]+$/, "");

    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = "https://" + clean;
    }
    try {
      const parsed = new URL(clean);
      if (parsed.hostname && parsed.hostname.includes(".")) {
        const canonical = parsed.toString();
        if (!seen.has(canonical.toLowerCase())) {
          seen.add(canonical.toLowerCase());
          normalizedUrls.push(canonical);
        }
      }
    } catch {
      // Ignore invalid URL parse
    }
  }

  return normalizedUrls;
}

/**
 * Redacts personally identifiable information (PII), credentials, phone numbers,
 * email addresses, financial identifiers, and government IDs from arbitrary user text.
 */
export function redactSensitivePii(text: string): { redactedText: string; redactions: string[] } {
  if (!text || typeof text !== "string") {
    return { redactedText: "", redactions: [] };
  }

  const redactions: string[] = [];
  let current = text;

  // 1. Credit/Debit Card numbers (13-16 digits with spaces or hyphens) - check BEFORE Aadhaar so 16-digit cards aren't truncated into 12-digit Aadhaar matches
  const cardRegex = /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b/g;
  if (cardRegex.test(current)) {
    redactions.push("Credit/Debit card number redacted");
    current = current.replace(cardRegex, "[CARD NUMBER REDACTED]");
  }

  // 2. Email addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  if (emailRegex.test(current)) {
    redactions.push("Email address redacted");
    current = current.replace(emailRegex, "[EMAIL REDACTED]");
  }

  // 3. Bank Account & IBAN Identifiers (prioritized before generic phone numbers)
  const ibanRegex = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
  if (ibanRegex.test(current)) {
    redactions.push("Bank account (IBAN) redacted");
    current = current.replace(ibanRegex, "[BANK ACCOUNT REDACTED]");
  }

  const bankAcctRegex = /(?:bank\s+account|account\s+number|a\/c\s+no|acct\s*#|account\s+)\s*[:=]?\s*([0-9]{8,18})\b/gi;
  if (bankAcctRegex.test(current)) {
    redactions.push("Bank account number redacted");
    current = current.replace(bankAcctRegex, (match, acct) => {
      return match.replace(acct, "[BANK ACCOUNT REDACTED]");
    });
  }

  // 4. Phone numbers (international, US, Indian 10-digit, UK formats)
  const phoneRegex =
    /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b(?:\+91[-.\s]?)?[6-9]\d{9}\b|(?:\+\d{1,4}[-.\s]?(?:\(?\d{1,5}\)?[-.\s]?){1,4}\d{2,6}\b)/g;
  if (phoneRegex.test(current)) {
    redactions.push("Phone number redacted");
    current = current.replace(phoneRegex, "[PHONE REDACTED]");
  }

  // 5. Indian PAN Card (5 letters, 4 digits, 1 letter)
  const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
  if (panRegex.test(current)) {
    redactions.push("Government ID (PAN) redacted");
    current = current.replace(panRegex, "[GOV ID REDACTED]");
  }

  // 6. Indian Aadhaar Card (exactly 12 digits, 3 groups of 4 digits, not part of a 16-digit card)
  const aadhaarRegex = /\b\d{4}\s\d{4}\s\d{4}\b(?!\s\d{4})/g;
  if (aadhaarRegex.test(current)) {
    redactions.push("Government ID (Aadhaar) redacted");
    current = current.replace(aadhaarRegex, "[GOV ID REDACTED]");
  }

  // 7. International Government IDs (US SSN: 3-2-4 digits, UK National Insurance Number)
  const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
  if (ssnRegex.test(current)) {
    redactions.push("Government ID (SSN) redacted");
    current = current.replace(ssnRegex, "[GOV ID REDACTED]");
  }

  const ninoRegex = /\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi;
  if (ninoRegex.test(current)) {
    redactions.push("Government ID (NINO) redacted");
    current = current.replace(ninoRegex, "[GOV ID REDACTED]");
  }

  // 8. Passwords, Credentials, and Secret Keys declared in text
  const credentialRegex =
    /(?:password|passwd|pwd|passcode|secret[-_ ]key|api[-_ ]key|access[-_ ]token|private[-_ ]key)\s*(?:is\s+|:\s*|=\s*|\s+)([^\s,.;]+)/gi;
  if (credentialRegex.test(current)) {
    redactions.push("Password / credential redacted");
    current = current.replace(credentialRegex, (match, credVal) => {
      return match.replace(credVal, "[CREDENTIAL REDACTED]");
    });
  }

  // 9. OTP / Verification codes following explicit OTP labels
  const otpRegex = /(?:otp|one[-_ ]time[-_ ]password|verification[-_ ]code|security[-_ ]pin|auth[-_ ]code|login[-_ ]code)\s*(?:is|:|=)?\s*([0-9a-zA-Z]{4,8})\b/gi;
  if (otpRegex.test(current)) {
    redactions.push("OTP / verification code redacted");
    current = current.replace(otpRegex, (match, code) => {
      return match.replace(code, "[CODE REDACTED]");
    });
  }

  // 10. Sensitive query parameters in URLs embedded in text (?token=..., &access_token=..., etc.)
  const sensitiveUrlParamRegex =
    /([?&](?:access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|session[-_]?token|sessionid|api[-_]?key|apikey|client[-_]?secret|private[-_]?key|password|passwd|pwd|otp|otp[-_]?code|token|secret|key|code|state|jwt|bearer)=)[^\s&"'#]+/gi;
  if (sensitiveUrlParamRegex.test(current)) {
    redactions.push("Sensitive URL query parameter redacted");
    current = current.replace(sensitiveUrlParamRegex, "$1[REDACTED]");
  }

  // 11. Sensitive URL hash fragments (#access_token=..., etc.)
  const sensitiveUrlFragmentRegex =
    /(#(?:access[-_]?token|id[-_]?token|token|auth|secret|key)=)[^\s&"'#]+/gi;
  if (sensitiveUrlFragmentRegex.test(current)) {
    redactions.push("Sensitive URL hash fragment redacted");
    current = current.replace(sensitiveUrlFragmentRegex, "$1[REDACTED]");
  }

  return { redactedText: current, redactions: Array.from(new Set(redactions)) };
}

/**
 * Extracts claimed organization or company name from message text.
 */
export function extractClaimedOrganization(text: string): string | undefined {
  if (!text) return undefined;

  // Patterns such as "team at Google", "from Microsoft", "Amazon HR", "working with Infosys", "hiring for Netflix"
  const patterns = [
    /(?:from|at|with|by|join|join\s+the\s+team\s+at)\s+([A-Z][A-Za-z0-9&.\s]{2,30}?)(?:\s+(?:HR|Team|Recruitment|Careers|Talent|Hiring|Group|Inc|LLC|Ltd|Technologies|Solutions|Services))?(?=[,.:;\n]|$)/i,
    /(?:offer\s+from|job\s+at|internship\s+at|contract\s+with)\s+([A-Z][A-Za-z0-9&.\s]{2,30}?)(?=[,.:;\n]|$)/i,
    /([A-Z][A-Za-z0-9&.\s]{2,25}?)\s+(?:HR\s+Team|Recruiting\s+Team|Talent\s+Acquisition|Careers\s+Team|Hiring\s+Manager)/i,
  ];

  for (const pat of patterns) {
    const match = text.match(pat);
    if (match?.[1]) {
      const candidate = match[1].trim();
      // Filter out generic filler words
      if (!/^(the|our|this|we|you|your|any|all|remote|online|global|urgent)$/i.test(candidate)) {
        return candidate.replace(/\s+(is|has|will|would|can|offers)$/i, "").trim();
      }
    }
  }

  return undefined;
}

/**
 * Extracts job title or internship role from message text.
 */
export function extractClaimedJobRole(text: string): string | undefined {
  if (!text) return undefined;

  const patterns = [
    /(?:position\s+of|role\s+of|hiring\s+for|selected\s+for|interview\s+for|apply\s+for)\s+(?:a\s+|an\s+)?([A-Za-z\s/]{3,40}?)(?:\s+(?:role|position|job|internship))?(?=[,.:;\n]|$)/i,
    /(?:software\s+engineer|data\s+analyst|content\s+writer|marketing\s+intern|product\s+manager|web\s+developer|qa\s+tester|customer\s+support\s+executive|graphic\s+designer|virtual\s+assistant|data\s+entry\s+operator|python\s+developer|frontend\s+developer|backend\s+developer)(?:\s+intern|\s+trainee|\s+specialist|\s+lead)?/i,
  ];

  for (const pat of patterns) {
    const match = text.match(pat);
    if (match?.[1]) {
      const candidate = match[1].trim();
      if (candidate.length >= 3 && candidate.length <= 50) return candidate;
    } else if (match?.[0]) {
      return match[0].trim();
    }
  }

  return undefined;
}

/**
 * Extracts stated compensation, salary, or stipend.
 */
export function extractCompensation(text: string): string | undefined {
  if (!text) return undefined;

  const patterns = [
    /(?:salary|stipend|ctc|package|pay|compensation)\s*(?:of|is|:)?\s*([$₹€£]\s*[0-9,.]+(?:\s*(?:k|lac|lakh|per\s+(?:month|annum|year|hr|hour|day)|[/-]\s*(?:mo|yr|hr))?))/i,
    /([$₹€£]\s*[0-9,.]+(?:\s*(?:k|lac|lakh|per\s+(?:month|annum|year|hr|hour|day)|[/-]\s*(?:mo|yr|hr))))/i,
    /([0-9,.]+\s*(?:INR|USD|EUR|GBP)\s*(?:per\s+(?:month|annum|year|hr|hour|day)|[/-]\s*(?:mo|yr|hr))?)/i,
  ];

  for (const pat of patterns) {
    const match = text.match(pat);
    if (match?.[1]) {
      return match[1].trim();
    }
  }

  return undefined;
}

/**
 * Detects whether a message explicitly requests an upfront recruitment/application fee,
 * distinguishing it from ordinary statements about candidate remuneration.
 */
export function detectRecruitmentFee(text: string): RecruitmentFeeWarning | undefined {
  if (!text) return undefined;

  // Exact matching for fee demand patterns
  const feePatterns: Array<{
    type: RecruitmentFeeWarning["feeType"];
    regex: RegExp;
    explanation: string;
  }> = [
    {
      type: "application_fee",
      regex: /(?:pay|deposit|transfer|send)\s+(?:(?:an?|the|any)\s+)?(?:(?:[$₹€£]\s*[0-9,.]+|[0-9,.]+\s*(?:rs|inr|usd)?)\s+)?(?:application|registration|processing|interview|portal|assessment)\s+fees?/i,
      explanation: "Legitimate employers never charge application or registration fees to evaluate candidates.",
    },
    {
      type: "security_deposit",
      regex: /(?:refundable\s+)?(?:security|caution|guarantee|equipment|laptop)\s+deposit/i,
      explanation: "Legitimate corporate recruiters do not ask candidates for refundable security deposits or equipment advance deposits.",
    },
    {
      type: "training_fee",
      regex: /(?:pay|charge|deposit)\s+(?:for\s+)?(?:mandatory\s+)?(?:training|induction|onboarding|course|orientation)(?:\s+[a-z]+)?\s+(?:fees?|charges?|costs?)/i,
      explanation: "Requiring candidates to purchase mandatory training prior to employment is a primary indicator of recruitment scams.",
    },
    {
      type: "equipment_fee",
      regex: /(?:pay|deposit|advance)\s+(?:(?:an?|the|a|any|[$₹€£]\s*[0-9,.]+|[0-9,.]+\s*(?:rs|inr|usd)?)\s+)?(?:for\s+)?(?:laptop|equipment|home\s+office|courier|dispatch|id\s+card|uniform)/i,
      explanation: "Legitimate companies provide company equipment and do not ask candidates to advance funds for laptops or uniforms.",
    },
    {
      type: "interview_fee",
      regex: /(?:pay|deposit)\s+(?:before|to\s+schedule|for)\s+(?:the\s+)?(?:interview|offer\s+letter|appointment)/i,
      explanation: "Interviews and offer releases are standard recruitment stages and are never paywalled by legitimate employers.",
    },
  ];

  for (const item of feePatterns) {
    const match = text.match(item.regex);
    if (match) {
      // Find surrounding sentence for quotation
      const index = match.index || 0;
      const start = Math.max(0, text.lastIndexOf(".", index) + 1);
      const end = text.indexOf(".", index + match[0].length);
      const quote = text.substring(start, end !== -1 ? end : undefined).trim();

      // Negative guard: If the sentence states that the employer pays or provides equipment/training free:
      const employerSubject = /(?:we|company|employer|firm|organization|sponsor)\s+(?:will\s+)?(?:pay|cover|absorb|provide|reimburse|bear)\s+(?:for\s+)?/i;
      const candidateFree = /(?:at\s+no\s+cost|free\s+of\s+charge|no\s+(?:application\s+)?fees?|100%\s+free|never\s+(?:charge|ask\s+for\s+money))\b/i;
      const candidateRequired = /(?:candidate|applicant|you)\s+(?:must|should|have\s+to|need\s+to|are\s+required\s+to|shall)\s+(?:pay|send|deposit|transfer)/i;

      if ((employerSubject.test(quote) || candidateFree.test(quote)) && !candidateRequired.test(quote)) {
        continue;
      }

      return {
        detected: true,
        feeType: item.type,
        quotedText: quote.length > 0 ? quote : match[0],
        explanation: item.explanation,
        riskLevel: "High",
      };
    }
  }

  // Catch general patterns: "pay [amount] to get this job/offer"
  const generalPayMatch = text.match(/(?:pay|send|transfer|deposit)\s+(?:[$₹€£]\s*[0-9,.]+|[0-9,.]+\s*(?:rs|inr|usd))\s+(?:to\s+(?:confirm|receive|get|claim|start)|for\s+(?:the\s+)?(?:job|offer|internship|training))/i);
  if (generalPayMatch) {
    const gIndex = generalPayMatch.index || 0;
    const gStart = Math.max(0, text.lastIndexOf(".", gIndex) + 1);
    const gEnd = text.indexOf(".", gIndex + generalPayMatch[0].length);
    const gQuote = text.substring(gStart, gEnd !== -1 ? gEnd : undefined).trim();
    const employerSubject = /(?:we|company|employer|firm|organization|sponsor)\s+(?:will\s+)?(?:pay|cover|absorb|provide|reimburse|bear)\b/i;
    const candidateRequired = /(?:candidate|applicant|you)\s+(?:must|should|have\s+to|need\s+to|are\s+required\s+to|shall)\s+(?:pay|send|deposit|transfer)/i;

    if (!employerSubject.test(gQuote) || candidateRequired.test(gQuote)) {
      return {
        detected: true,
        feeType: "unspecified_fee",
        quotedText: generalPayMatch[0],
        explanation: "The message instructs the candidate to send funds to secure employment or complete the hiring process.",
        riskLevel: "High",
      };
    }
  }

  return undefined;
}

/**
 * Detects payment requests in text, with explicit distinction between
 * asking the user to send money vs benign statements about being paid.
 */
export function detectPaymentRisks(text: string, targetUrl?: string): PaymentRiskItem[] {
  if (!text) return [];
  const risks: PaymentRiskItem[] = [];

  // 1. Fee for job / employment
  const feeWarning = detectRecruitmentFee(text);
  if (feeWarning) {
    risks.push({
      id: "pay-risk-job-fee",
      paymentType: "fee_for_job",
      quotedText: feeWarning.quotedText,
      cautionReason: "Recruitment fee demanded: " + feeWarning.explanation,
      destinationInvestigated: Boolean(targetUrl),
      evidenceSummary: `Message contains explicit demand: "${feeWarning.quotedText}"`,
      recommendedVerificationStep: "Do not transfer money. Check the company's verified careers portal directly.",
    });
  }

  // 2. Personal P2P / UPI transfer requests
  const p2pRegex = /(?:send\s+(?:money|funds|payment)\s+to|pay\s+via|transfer\s+to)\s+(?:gpay|phonepe|paytm|upi(?:\s+id)?|paypal|crypto|bitcoin|usdt|wire|western\s+union|account\s+number)\b[:\s]*([a-zA-Z0-9._\-@]+)/i;
  const p2pMatch = text.match(p2pRegex);
  if (p2pMatch) {
    const handle = p2pMatch[1]?.trim();
    const idx = p2pMatch.index ?? 0;
    const start = Math.max(0, text.lastIndexOf(".", idx) + 1);
    const end = text.indexOf(".", idx + p2pMatch[0].length);
    const quote = text.substring(start, end !== -1 ? end : undefined).trim();

    risks.push({
      id: "pay-risk-p2p",
      paymentType: "p2p_transfer",
      quotedText: quote.length > 0 ? quote : p2pMatch[0].trim(),
      claimedRecipient: handle || "Unverified personal account",
      cautionReason: "Payment instructions direct money to peer-to-peer wallets, individual UPI handles, or crypto accounts rather than corporate billing systems.",
      destinationInvestigated: Boolean(targetUrl),
      evidenceSummary: `Direct payment channel specified: "${quote || p2pMatch[0].trim()}"`,
      recommendedVerificationStep: "Corporate fees or services are never billed to personal UPI, cryptocurrency wallets, or peer-to-peer accounts.",
    });
  }

  // 3. Urgent advance payment
  const urgentPayMatch = text.match(/(?:urgent|immediate|within\s+\d+\s+(?:hours?|minutes?))\s+(?:payment|transfer|deposit)\s+(?:is\s+)?required/i);
  if (urgentPayMatch) {
    risks.push({
      id: "pay-risk-urgent",
      paymentType: "urgent_fee",
      quotedText: urgentPayMatch[0].trim(),
      cautionReason: "Urgency tactics are used to bypass critical thinking and force immediate fund transfers.",
      destinationInvestigated: Boolean(targetUrl),
      evidenceSummary: `Urgent payment pressure: "${urgentPayMatch[0].trim()}"`,
      recommendedVerificationStep: "Pause and independently contact the purported organization via their official published support number.",
    });
  }

  return risks;
}

/**
 * Extracts requests for sensitive personal information, credentials, or identity documents,
 * distinguishing requests to disclose from informational mentions.
 */
export function detectSensitiveDataRequests(text: string): SensitiveDataRequestItem[] {
  if (!text) return [];
  const items: SensitiveDataRequestItem[] = [];

  const checkConfigs: Array<{
    category: SensitiveDataRequestItem["dataCategory"];
    requestRegex: RegExp;
    riskExplanation: string;
  }> = [
    {
      category: "password",
      requestRegex: /(?:send|share|provide|enter|submit|reply\s+with)\s+(?:your\s+)?password/i,
      riskExplanation: "Legitimate organizations never ask for your password over email, WhatsApp, or SMS.",
    },
    {
      category: "otp_2fa",
      requestRegex: /(?:send|share|forward|provide|verify\s+using)\s+(?:the\s+)?(?:otp|one[- ]time[- ]password|verification\s+code|2fa\s+code)/i,
      riskExplanation: "OTPs grant direct access to your accounts. Sharing an OTP allows attackers to hijack your identity or funds.",
    },
    {
      category: "card_details",
      requestRegex: /(?:enter|provide|send|share)\s+(?:your\s+)?(?:card\s+number|cvv|cvc|card\s+expiry|debit\s+card\s+details|credit\s+card\s+details)/i,
      riskExplanation: "Requesting raw payment card credentials outside a secure, verified payment gateway exposes you to financial theft.",
    },
    {
      category: "bank_account",
      requestRegex: /(?:send|share|provide)\s+(?:your\s+)?(?:bank\s+account\s+number|ifsc\s+code|internet\s+banking\s+credentials|atm\s+pin)/i,
      riskExplanation: "Banking credentials and ATM PINs must never be disclosed through messages or unverified links.",
    },
    {
      category: "government_id",
      requestRegex: /(?:upload|send|share|email)\s+(?:your\s+)?(?:aadhaar|pan\s+card|passport\s+copy|social\s+security|ssn|driving\s+license)\s+(?:to\s+(?:proceed|complete|receive)|over\s+whatsapp)/i,
      riskExplanation: "Sending government identity documents through unverified communication channels creates severe identity theft risks.",
    },
  ];

  for (const cfg of checkConfigs) {
    const match = text.match(cfg.requestRegex);
    if (match) {
      items.push({
        id: `sens-req-${cfg.category}`,
        dataCategory: cfg.category,
        source: "message_text_request",
        quotedText: match[0],
        riskExplanation: cfg.riskExplanation,
        isDestinationVerified: false,
      });
    }
  }

  return items;
}

/**
 * Extracts structured claims from message text for claim-by-claim verification.
 */
export function extractClaimsFromMessage(params: {
  text: string;
  claimedOrg?: string;
  claimedRole?: string;
  compensation?: string;
  feeWarning?: RecruitmentFeeWarning;
  paymentRisks: PaymentRiskItem[];
  sensitiveDataRequests: SensitiveDataRequestItem[];
}): ClaimRecord[] {
  const { text, claimedOrg, claimedRole, compensation, feeWarning, paymentRisks, sensitiveDataRequests } = params;
  const claims: ClaimRecord[] = [];
  const now = new Date().toISOString();

  // 1. Organization Identity Claim
  if (claimedOrg) {
    claims.push({
      id: "claim-org-identity",
      category: "employer_identity",
      claimText: `The message asserts affiliation with or representation of "${claimedOrg}".`,
      claimedOrganization: claimedOrg,
      evaluation: "Unverified",
      explanation: `The sender claims to represent "${claimedOrg}". Verification requires checking the destination domain against the official company registry.`,
      provenance: "message_text",
      retrievedAt: now,
      limitations: "Identity claimed in prose is an unverified assertion until corroborated by official DNS and domain ownership.",
    });
  }

  // 2. Job Role Claim
  if (claimedRole) {
    claims.push({
      id: "claim-job-role",
      category: "job_role",
      claimText: `The message offers or references the role: "${claimedRole}".`,
      claimedOrganization: claimedOrg,
      evaluation: "Unverified",
      explanation: `Role "${claimedRole}" was claimed in the message. Official careers pages must be checked to confirm if this vacancy exists.`,
      provenance: "message_text",
      retrievedAt: now,
      limitations: "Absence of a matching public job post does not definitively prove fraud (roles may be unlisted or newly published), but warrants caution.",
    });
  }

  // 3. Compensation Claim
  if (compensation) {
    claims.push({
      id: "claim-compensation",
      category: "compensation",
      claimText: `Stated remuneration: ${compensation}.`,
      claimedOrganization: claimedOrg,
      evaluation: "Unverified",
      explanation: `The message promises compensation of ${compensation}. Unusually inflated pay for entry-level tasks is a common lure in employment fraud.`,
      provenance: "message_text",
      retrievedAt: now,
    });
  }

  // 4. Recruitment Fee Claim
  if (feeWarning) {
    claims.push({
      id: "claim-recruitment-fee",
      category: "recruitment_fee",
      claimText: `Payment requested for employment: "${feeWarning.quotedText}".`,
      claimedOrganization: claimedOrg,
      evaluation: "Contradicted",
      explanation: `The message demands money (${feeWarning.feeType?.replace("_", " ")}). This contradicts ethical hiring standards and official corporate policies of legitimate organizations.`,
      provenance: "message_text",
      retrievedAt: now,
      limitations: "Direct contradiction: established companies universally disclaim charging applicants fees.",
    });
  }

  // 5. Payment Risk Claims
  for (const pr of paymentRisks) {
    if (pr.paymentType !== "fee_for_job") {
      claims.push({
        id: `claim-pay-${pr.paymentType}`,
        category: "compensation",
        claimText: `Payment instruction: "${pr.quotedText}".`,
        claimedOrganization: claimedOrg,
        evaluation: "Contradicted",
        explanation: pr.cautionReason,
        provenance: "message_text",
        retrievedAt: now,
      });
    }
  }

  // 6. Sensitive Data Request Claims
  for (const s of sensitiveDataRequests) {
    claims.push({
      id: `claim-sens-${s.dataCategory}`,
      category: "sensitive_data",
      claimText: `Requests disclosure of ${s.dataCategory.replace("_", " ")}: "${s.quotedText || s.dataCategory}".`,
      claimedOrganization: claimedOrg,
      evaluation: "Contradicted",
      explanation: s.riskExplanation,
      provenance: "message_text",
      retrievedAt: now,
    });
  }

  // 7. Guaranteed Hiring / Task Scam Claims
  const guaranteedMatch = text.match(/(?:100%|guaranteed)\s+(?:selection|job|placement|hiring)|(?:no\s+interview\s+(?:needed|required))/i);
  if (guaranteedMatch) {
    claims.push({
      id: "claim-guaranteed-hiring",
      category: "guaranteed_hiring",
      claimText: `Promise of unconditional employment: "${guaranteedMatch[0]}".`,
      claimedOrganization: claimedOrg,
      evaluation: "Contradicted",
      explanation: "No legitimate corporate organization guarantees employment or bypasses competency assessment entirely without an interview.",
      provenance: "message_text",
      retrievedAt: now,
    });
  }

  return claims;
}

/**
 * End-to-end analysis of message text, performing extraction, PII redaction,
 * risk detection, and structured claim formulation.
 */
export function analyzeMessageText(params: {
  rawMessage: string;
  userSpecifiedOrg?: string;
  userSpecifiedRole?: string;
  targetUrl?: string;
}): ExtractedMessageData {
  const { rawMessage, userSpecifiedOrg, userSpecifiedRole, targetUrl } = params;

  // 1. Redact PII
  const { redactedText, redactions } = redactSensitivePii(rawMessage);

  // 2. Extract URLs
  const extractedUrls = extractUrlsFromText(rawMessage);
  const singleExtractedUrl = extractedUrls.length === 1 ? extractedUrls[0] : undefined;

  // 3. Organization and Role
  const claimedOrg = userSpecifiedOrg?.trim() || extractClaimedOrganization(rawMessage);
  const claimedJobRole = userSpecifiedRole?.trim() || extractClaimedJobRole(rawMessage);
  const claimedCompensation = extractCompensation(rawMessage);

  // 4. Recruitment Fee & Payment Risks
  const feeWarning = detectRecruitmentFee(rawMessage);
  const paymentRisks = detectPaymentRisks(rawMessage, targetUrl || singleExtractedUrl);

  // 5. Sensitive Data Requests
  const sensitiveDataRequests = detectSensitiveDataRequests(rawMessage);

  // 6. Structured Claims
  const claims = extractClaimsFromMessage({
    text: rawMessage,
    claimedOrg,
    claimedRole: claimedJobRole,
    compensation: claimedCompensation,
    feeWarning,
    paymentRisks,
    sensitiveDataRequests,
  });

  return {
    originalText: rawMessage,
    redactedText,
    extractedUrls,
    singleExtractedUrl,
    claimedOrganization: claimedOrg,
    claimedJobRole,
    claimedCompensation,
    recruitmentFeeWarning: feeWarning,
    paymentRisks,
    sensitiveDataRequests,
    claims,
    appliedRedactions: redactions,
  };
}
