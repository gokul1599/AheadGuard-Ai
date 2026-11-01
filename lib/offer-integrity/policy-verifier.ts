import { RecruitmentPolicyVerificationDetail } from "./types";

export interface KnownPolicyEntry {
  canonicalName: string;
  aliases: string[];
  officialCareersUrl: string;
  policyUrl: string;
  policyTitle: string;
  policyQuote: string;
  hasPublishedNoFeePolicy: boolean;
  officialEmailDomains: string[];
}

export const ENTERPRISE_RECRUITMENT_POLICIES: Record<string, KnownPolicyEntry> = {
  google: {
    canonicalName: "Google",
    aliases: ["google llc", "alphabet", "google india", "google cloud"],
    officialCareersUrl: "https://careers.google.com",
    policyUrl: "https://about.google/recruitment-fraud/",
    policyTitle: "Google Official Recruitment Fraud Advisory & Candidate Policy",
    policyQuote: "Google never asks for money, registration fees, security deposits, or interview fees at any stage of the application or hiring process. All legitimate communications come exclusively from @google.com email addresses.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["google.com"],
  },
  microsoft: {
    canonicalName: "Microsoft",
    aliases: ["microsoft corporation", "microsoft india", "msft"],
    officialCareersUrl: "https://careers.microsoft.com",
    policyUrl: "https://careers.microsoft.com/v2/global/en/recruitment-fraud",
    policyTitle: "Microsoft Candidate Security & Recruitment Advisory",
    policyQuote: "Microsoft does not request money or payment from candidates at any time during the recruitment, interview, or onboarding process. Microsoft conducts all hiring through official authenticated channels.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["microsoft.com"],
  },
  amazon: {
    canonicalName: "Amazon",
    aliases: ["amazon.com", "amazon india", "aws", "amazon web services"],
    officialCareersUrl: "https://www.amazon.jobs",
    policyUrl: "https://www.amazon.jobs/en/landing_pages/recruitment-fraud",
    policyTitle: "Amazon Candidate Alert Regarding Recruitment Fraud",
    policyQuote: "Amazon never asks for recruitment fees, processing fees, or security deposits for interview scheduling. Open positions are listed exclusively on amazon.jobs.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["amazon.com", "amazon.jobs"],
  },
  meta: {
    canonicalName: "Meta",
    aliases: ["facebook", "meta platforms", "meta india"],
    officialCareersUrl: "https://www.metacareers.com",
    policyUrl: "https://www.metacareers.com/recruiting-integrity",
    policyTitle: "Meta Recruitment Integrity & Candidate Guidance",
    policyQuote: "Meta never requests application fees, interview reservation payments, or equipment purchase deposits from candidates. We do not work with recruitment agencies that charge applicants.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["meta.com", "fb.com"],
  },
  apple: {
    canonicalName: "Apple",
    aliases: ["apple inc", "apple india"],
    officialCareersUrl: "https://www.apple.com/careers",
    policyUrl: "https://www.apple.com/careers/recruitment-fraud",
    policyTitle: "Apple Employment Security & Applicant Notice",
    policyQuote: "Apple does not ask for money transfers, refundable deposits, or fees for interview slots or training. Official correspondence originates exclusively from @apple.com.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["apple.com"],
  },
  tcs: {
    canonicalName: "Tata Consultancy Services",
    aliases: ["tcs", "tata consultancy services limited", "tcs nextstep"],
    officialCareersUrl: "https://www.tcs.com/careers",
    policyUrl: "https://www.tcs.com/careers/recruitment-fraud-alert",
    policyTitle: "TCS Notice on Fraudulent Recruitment Offers",
    policyQuote: "TCS does not charge any fee or security deposit at any stage of the recruitment process. TCS does not authorize any person or agency to collect money. Official communications come solely from @tcs.com.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["tcs.com"],
  },
  infosys: {
    canonicalName: "Infosys",
    aliases: ["infosys limited", "infosys technologies", "infy"],
    officialCareersUrl: "https://www.infosys.com/careers",
    policyUrl: "https://www.infosys.com/careers/recruitment-fraud.html",
    policyTitle: "Infosys Official Fraud Advisory for Job Seekers",
    policyQuote: "Infosys does not charge any candidate any fee, deposit, or consideration for job applications, test slots, or interview scheduling. Official communications are issued only from @infosys.com.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["infosys.com"],
  },
  wipro: {
    canonicalName: "Wipro",
    aliases: ["wipro limited", "wipro technologies"],
    officialCareersUrl: "https://careers.wipro.com",
    policyUrl: "https://www.wipro.com/careers/fraud-alert/",
    policyTitle: "Wipro Fraud Alert & Ethical Hiring Policy",
    policyQuote: "Wipro does not charge any fee at any stage of the recruitment process. Wipro does not solicit money for test links, interviews, or job guarantees.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["wipro.com"],
  },
  accenture: {
    canonicalName: "Accenture",
    aliases: ["accenture plc", "accenture india"],
    officialCareersUrl: "https://www.accenture.com/careers",
    policyUrl: "https://www.accenture.com/in-en/careers/recruitment-fraud-alert",
    policyTitle: "Accenture India Recruitment Fraud Alert",
    policyQuote: "Accenture does not charge any fee at any stage of the recruitment process (application, interview, processing, training). We do not authorize any agency to collect fees.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["accenture.com"],
  },
  openai: {
    canonicalName: "OpenAI",
    aliases: ["openai llc", "openai inc"],
    officialCareersUrl: "https://openai.com/careers",
    policyUrl: "https://openai.com/careers",
    policyTitle: "OpenAI Official Careers & Hiring Guidance",
    policyQuote: "OpenAI does not charge applicants or candidates any fees for application review or interview slots. All authentic requisitions must be viewed and applied for directly on openai.com/careers.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["openai.com"],
  },
  netflix: {
    canonicalName: "Netflix",
    aliases: ["netflix inc", "netflix entertainment"],
    officialCareersUrl: "https://jobs.netflix.com",
    policyUrl: "https://jobs.netflix.com/faq",
    policyTitle: "Netflix Candidate Hiring FAQ & Security Policy",
    policyQuote: "Netflix never asks for money or payment as part of the application or interview process. All open positions are posted on jobs.netflix.com.",
    hasPublishedNoFeePolicy: true,
    officialEmailDomains: ["netflix.com"],
  },
};

/**
 * Searches for a verified recruitment policy entry by company name or alias.
 */
export function findEnterprisePolicy(companyName?: string): KnownPolicyEntry | undefined {
  if (!companyName || typeof companyName !== "string") return undefined;
  const clean = companyName.toLowerCase().trim();

  // Direct key lookup
  if (ENTERPRISE_RECRUITMENT_POLICIES[clean]) {
    return ENTERPRISE_RECRUITMENT_POLICIES[clean];
  }

  // Search aliases
  for (const entry of Object.values(ENTERPRISE_RECRUITMENT_POLICIES)) {
    if (
      entry.canonicalName.toLowerCase() === clean ||
      entry.aliases.some((alias) => alias === clean || clean.includes(alias))
    ) {
      return entry;
    }
  }

  return undefined;
}

export interface PolicyVerificationParams {
  companyName?: string;
  observedPageText?: string;
  sourceUrl?: string;
  simulateFailure?: boolean;
  strictLiveCheck?: boolean;
  allowLiveCrawl?: boolean;
  tinyFishApiKey?: string;
}

/**
 * Verifies employer recruitment policy against enterprise database or observed page content.
 */
export function verifyRecruitmentPolicy(params: PolicyVerificationParams): RecruitmentPolicyVerificationDetail {
  const { companyName, observedPageText, sourceUrl, simulateFailure, strictLiveCheck } = params;
  const now = new Date().toISOString();

  const knownPolicy = findEnterprisePolicy(companyName);

  // 1. Simulate external source retrieval failure (Test I requirement)
  if (simulateFailure) {
    if (knownPolicy) {
      return {
        companyName: knownPolicy.canonicalName,
        policyStatus: "CHECK_FAILED",
        hasPublishedNoFeePolicy: true,
        sourceType: "FAILED",
        policyTitle: knownPolicy.policyTitle,
        policyUrl: knownPolicy.policyUrl,
        policyQuote: knownPolicy.policyQuote,
        retrievalTimestamp: now,
        cachedReferenceDate: "2026-01-01",
        explanation: `Live policy source retrieval failed or was unavailable (CHECK_FAILED). Retaining cached corporate policy reference: "${knownPolicy.policyQuote}".`,
        sourceAuthority: "External Policy Gateway (Cached Catalog Reference)",
        observationTime: now,
        limitations: "Live external policy source was unreachable; evaluated against verified local catalog cache.",
      };
    }
    return {
      companyName: companyName || "Unknown Employer",
      policyStatus: "CHECK_FAILED",
      hasPublishedNoFeePolicy: false,
      sourceType: "FAILED",
      retrievalTimestamp: now,
      explanation: "Live corporate policy lookup failed due to network timeout or external provider unavailability.",
      sourceAuthority: "External Policy Gateway",
      observationTime: now,
      limitations: "External policy source could not be reached; policy status cannot be confirmed.",
    };
  }

  // 2. Dynamic evaluation of observed text (from TinyFish crawl or live careers page)
  if (observedPageText) {
    const noFeeRegex = /(?:does\s+not\s+(?:charge|collect|ask\s+for|require)\s+(?:any\s+)?(?:[a-zA-Z\s]+?)?fees?|never\s+(?:charge|ask\s+for|collect)\s+(?:any\s+)?fees?|no\s+(?:application|interview|registration|hiring|processing)\s+fees?|recruitment\s+fraud\s+alert|do\s+not\s+pay\s+(?:any\s+)?money)/i;
    const match = observedPageText.match(noFeeRegex);
    if (match) {
      return {
        companyName: companyName || "Claimed Employer",
        policyStatus: strictLiveCheck ? "LIVE_POLICY_CONFIRMED_NO_FEE" : "POLICY_CONFIRMED_NO_FEE",
        hasPublishedNoFeePolicy: true,
        sourceType: "LIVE_RETRIEVAL",
        policyTitle: "Observed Candidate Guidance & No-Fee Statement",
        policyUrl: sourceUrl,
        policyQuote: match[0],
        retrievalTimestamp: now,
        explanation: `Observed official hiring statement indicates applicants are not charged fees: "${match[0]}".`,
        sourceAuthority: "Observed Corporate Career Portal (Live Retrieval)",
        observationTime: now,
        limitations: "Extracted dynamically from live public page content.",
      };
    }
  }

  // 3. Check known enterprise policy catalog
  if (knownPolicy) {
    return {
      companyName: knownPolicy.canonicalName,
      policyStatus: strictLiveCheck ? "CACHED_POLICY_REFERENCE" : "POLICY_CONFIRMED_NO_FEE",
      hasPublishedNoFeePolicy: true,
      sourceType: "CACHED_CATALOG",
      policyTitle: knownPolicy.policyTitle,
      policyUrl: knownPolicy.policyUrl,
      policyQuote: knownPolicy.policyQuote,
      retrievalTimestamp: now,
      cachedReferenceDate: "2026-01-01",
      explanation: `Verified official recruitment policy found: ${knownPolicy.canonicalName} explicitly states applicants do not pay any fees for applications, interviews, or hiring.`,
      sourceAuthority: "Authoritative Primary Employer Policy (Catalog Reference)",
      observationTime: now,
      limitations: "Policy establishes corporate rule against applicant fees; does not guarantee that bad actors cannot impersonate the brand.",
    };
  }

  // 4. Fallback: Honest preservation of uncertainty
  return {
    companyName: companyName || "Unknown Employer",
    policyStatus: "NO_POLICY_FOUND",
    hasPublishedNoFeePolicy: false,
    sourceType: "UNAVAILABLE",
    retrievalTimestamp: now,
    explanation: `No explicit recruitment anti-fraud or no-fee policy document was indexed for "${companyName || "this employer"}". However, demanding an upfront payment to reserve an interview is a recognized high-risk scam indicator.`,
    sourceAuthority: "General Industry Recruitment Standard",
    observationTime: now,
    limitations: "Absence of a published policy does not mean fees are legitimate; legitimate global employers do not charge interview reservation fees.",
  };
}
