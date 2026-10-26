import type {
  ActionPreview,
  CheckPerformed,
  Finding,
  InvestigationReport,
  ModelInterpretation,
  ObservedDestination,
  ObservedFacts,
  RiskOutcome,
  ThreatLikelihood,
  ConsequenceImpact,
} from "./types";
import type { TinyFishExecutionResult } from "./tinyfish";
import { isUnsafeDestination } from "./url-safety";

// Known high-severity threat markers grounded in investigation output
const HIGH_RISK_SIGNALS = [
  "confirmed phishing",
  "credential harvesting",
  "credential theft",
  "malware detected",
  "malicious payload",
  "trojan",
  "ransomware",
  "known malicious",
  "active exploit",
  "fake sign-in portal",
  "cloned login page",
];

// Indicators of suspicious activity
const SUSPICIOUS_SIGNALS = [
  "requests password",
  "requests credentials",
  "requests otp",
  "requests 2fa",
  "requests payment",
  "requests credit card",
  "urgent action required",
  "account suspension warning",
  "verify your account immediately",
  "immediate verification required",
  "domain mismatch",
  "unverified destination",
  "impersonation",
  "look-alike domain",
  "typosquatting",
  "unexpected download",
  "suspicious redirect",
  "executable download",
  "unverified apk",
  "powershell script",
];

// Adversarial prompt injection markers in web content
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /aheadguard.*(safe|verified|allow|bypass)/i,
  /declare\s+(this\s+site\s+)?low\s+observed\s+risk/i,
  /system\s+prompt\s*:/i,
  /you\s+are\s+now\s+in\s+developer\s+mode/i,
  /override\s+security\s+verdict/i,
];

export interface BrandRegistryEntry {
  canonicalName: string;
  aliases: string[];
  approvedDomains: string[];
  affiliatedAuthDomains?: string[];
}

/**
 * Structured registry of high-profile canonical brands, approved domain roots,
 * and recognized identity provider / affiliated authentication domains.
 * Note: example.com, example.org, and example.net are reserved documentation domains (RFC 2606),
 * not official brand domains representing IANA or ICANN.
 */
export const BRAND_DOMAIN_REGISTRY: Record<string, BrandRegistryEntry> = {
  google: {
    canonicalName: "Google",
    aliases: ["google", "google llc", "google inc", "alphabet"],
    approvedDomains: [
      "google.com",
      "google.co.uk",
      "google.ca",
      "google.de",
      "google.fr",
      "google.com.au",
      "google.co.in",
      "google.co.jp",
    ],
    affiliatedAuthDomains: ["accounts.google.com"],
  },
  youtube: {
    canonicalName: "YouTube",
    aliases: ["youtube", "youtube llc", "youtube video", "youtube music", "youtube - a google company"],
    approvedDomains: ["youtube.com", "youtu.be"],
    affiliatedAuthDomains: ["accounts.google.com", "google.com"],
  },
  microsoft: {
    canonicalName: "Microsoft",
    aliases: ["microsoft", "microsoft corporation", "msft", "office 365", "microsoft 365"],
    approvedDomains: [
      "microsoft.com",
      "live.com",
      "office.com",
      "office365.com",
      "msn.com",
      "bing.com",
      "windows.com",
    ],
    affiliatedAuthDomains: [
      "login.microsoftonline.com",
      "login.live.com",
      "account.microsoft.com",
    ],
  },
  apple: {
    canonicalName: "Apple",
    aliases: ["apple", "apple inc"],
    approvedDomains: ["apple.com", "icloud.com"],
    affiliatedAuthDomains: ["appleid.apple.com"],
  },
  amazon: {
    canonicalName: "Amazon",
    aliases: ["amazon", "amazon.com", "amazon inc"],
    approvedDomains: [
      "amazon.com",
      "amazon.co.uk",
      "amazon.de",
      "amazon.co.jp",
      "amazon.fr",
      "amazon.ca",
      "amazon.in",
      "aws.amazon.com",
    ],
    affiliatedAuthDomains: ["signin.aws.amazon.com"],
  },
  paypal: {
    canonicalName: "PayPal",
    aliases: ["paypal", "paypal inc"],
    approvedDomains: ["paypal.com", "paypal.me"],
    affiliatedAuthDomains: [],
  },
  meta: {
    canonicalName: "Meta",
    aliases: ["meta", "meta platforms", "facebook", "instagram", "whatsapp"],
    approvedDomains: ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "fb.com"],
    affiliatedAuthDomains: [],
  },
  netflix: {
    canonicalName: "Netflix",
    aliases: ["netflix", "netflix inc"],
    approvedDomains: ["netflix.com"],
    affiliatedAuthDomains: [],
  },
  wikimedia: {
    canonicalName: "Wikimedia Foundation",
    aliases: ["wikimedia", "wikimedia foundation", "wikipedia"],
    approvedDomains: ["wikipedia.org", "wikimedia.org", "wiktionary.org", "wikidata.org"],
    affiliatedAuthDomains: [],
  },
  iana: {
    canonicalName: "Internet Assigned Numbers Authority (IANA)",
    aliases: ["iana", "internet assigned numbers authority"],
    approvedDomains: ["iana.org"],
    affiliatedAuthDomains: [],
  },
  github: {
    canonicalName: "GitHub",
    aliases: ["github", "github inc"],
    approvedDomains: ["github.com", "github.io"],
    affiliatedAuthDomains: [],
  },
  chase: {
    canonicalName: "Chase",
    aliases: ["chase", "jpmorgan chase", "chase bank"],
    approvedDomains: ["chase.com"],
    affiliatedAuthDomains: [],
  },
  bankofamerica: {
    canonicalName: "Bank of America",
    aliases: ["bank of america", "bofa"],
    approvedDomains: ["bankofamerica.com"],
    affiliatedAuthDomains: [],
  },
  wellsfargo: {
    canonicalName: "Wells Fargo",
    aliases: ["wells fargo", "wells fargo bank"],
    approvedDomains: ["wellsfargo.com"],
    affiliatedAuthDomains: [],
  },
};

/**
 * Checks whether a given hostname is an officially reserved example/documentation domain (RFC 2606 / RFC 6761).
 */
export function isReservedExampleDomain(hostname: string): boolean {
  if (!hostname) return false;
  const h = hostname.toLowerCase().trim();
  return (
    h === "example.com" ||
    h === "example.org" ||
    h === "example.net" ||
    h === "example.edu" ||
    h.endsWith(".example.com") ||
    h.endsWith(".example.org") ||
    h.endsWith(".example.net") ||
    h.endsWith(".example.edu") ||
    h === "example" ||
    h.endsWith(".example")
  );
}

/**
 * Checks whether a given hostname matches an approved root domain or is a subdomain of it.
 * Enforces strict domain boundaries: 'www.youtube.com' matches 'youtube.com', but
 * 'youtube-phish.com' does NOT match 'youtube.com'.
 */
export function isDomainOrSubdomain(hostname: string, domainOrRoot: string): boolean {
  if (!hostname || !domainOrRoot) return false;
  const normHost = hostname.toLowerCase().trim();
  const normRoot = domainOrRoot.toLowerCase().trim();
  if (normHost === normRoot) return true;
  if (normHost.endsWith("." + normRoot)) return true;
  return false;
}

/**
 * Extracts a concise canonical brand name from claimed organization text.
 * Strips explanatory suffixes, parentheticals, and corporate entity abbreviations.
 */
export function extractCanonicalBrandName(claimedOrg: string): string {
  if (!claimedOrg) return "";
  let cleaned = claimedOrg.trim();
  // Strip parentheticals like "(Google)", "(US)"
  cleaned = cleaned.replace(/\s*\([^)]*\)/g, "").trim();
  // Split on dash, hyphen, pipe, bullet, colon if descriptive
  const parts = cleaned.split(/[-–—|•:]/);
  if (parts.length > 0 && parts[0].trim().length > 0) {
    cleaned = parts[0].trim();
  }
  // Strip trailing inc, llc, corp, ltd, co
  cleaned = cleaned.replace(/\s*,?\s*(llc|inc\.?|corp\.?|corporation|ltd\.?|limited|co\.?|company)$/i, "").trim();
  return cleaned;
}

export interface BrandAffiliationResult {
  isRegisteredBrand: boolean;
  brandEntry?: BrandRegistryEntry;
  canonicalBrand: string;
  isOfficialDomain: boolean;
  isAffiliatedDomain: boolean;
  hasMismatch: boolean;
  isReservedExample?: boolean;
  reason?: string;
}

/**
 * Evaluates claimed organization against the destination hostname using the structured registry.
 */
export function evaluateBrandAffiliation(
  claimedOrg: string | undefined,
  hostname: string
): BrandAffiliationResult {
  // 1. Reserved documentation / example domains (RFC 2606) do not claim corporate identities
  if (isReservedExampleDomain(hostname)) {
    return {
      isRegisteredBrand: false,
      canonicalBrand: "",
      isOfficialDomain: false,
      isAffiliatedDomain: false,
      hasMismatch: false,
      isReservedExample: true,
      reason: "Reserved documentation/example domain (RFC 2606); references to third-party organizations are informational.",
    };
  }

  if (!claimedOrg || !claimedOrg.trim()) {
    return {
      isRegisteredBrand: false,
      canonicalBrand: "",
      isOfficialDomain: false,
      isAffiliatedDomain: false,
      hasMismatch: false,
    };
  }

  const rawOrgLower = claimedOrg.toLowerCase().trim();
  const canonical = extractCanonicalBrandName(claimedOrg);
  const canonicalLower = canonical.toLowerCase().trim();

  // Find if claimedOrg matches any known entry in the BRAND_DOMAIN_REGISTRY
  let matchedEntry: BrandRegistryEntry | undefined;
  for (const entry of Object.values(BRAND_DOMAIN_REGISTRY)) {
    const entryNameLower = entry.canonicalName.toLowerCase();
    if (
      entryNameLower === canonicalLower ||
      entryNameLower === rawOrgLower ||
      entry.aliases.some(
        (alias) =>
          alias === canonicalLower ||
          alias === rawOrgLower ||
          rawOrgLower.startsWith(alias) ||
          canonicalLower.startsWith(alias)
      )
    ) {
      matchedEntry = entry;
      break;
    }
  }

  if (!matchedEntry) {
    // Unregistered brand: We DO NOT declare a mismatch warning based on guesses.
    return {
      isRegisteredBrand: false,
      canonicalBrand: canonical || claimedOrg,
      isOfficialDomain: false,
      isAffiliatedDomain: false,
      hasMismatch: false,
      reason: `Ownership of claimed organization "${claimedOrg}" is not in the recognized brand registry.`,
    };
  }

  // Brand is in registry. Check if hostname matches any approved domain or affiliated domain
  const isOfficial = matchedEntry.approvedDomains.some((d) => isDomainOrSubdomain(hostname, d));
  const isAffiliated = (matchedEntry.affiliatedAuthDomains || []).some((d) => isDomainOrSubdomain(hostname, d));

  if (isOfficial || isAffiliated) {
    return {
      isRegisteredBrand: true,
      brandEntry: matchedEntry,
      canonicalBrand: matchedEntry.canonicalName,
      isOfficialDomain: isOfficial,
      isAffiliatedDomain: isAffiliated,
      hasMismatch: false,
    };
  }

  // Brand is recognized, but hostname does NOT match approved or affiliated domains!
  return {
    isRegisteredBrand: true,
    brandEntry: matchedEntry,
    canonicalBrand: matchedEntry.canonicalName,
    isOfficialDomain: false,
    isAffiliatedDomain: false,
    hasMismatch: true,
    reason: `The page claims to represent "${matchedEntry.canonicalName}", but the domain (${hostname}) is not an approved official domain (${matchedEntry.approvedDomains.join(", ")}).`,
  };
}

/**
 * Checks if a redirection from fromHost to toHost is an approved affiliated redirection
 * (e.g. YouTube redirecting to accounts.google.com for login).
 */
export function isAffiliatedRedirection(fromHost: string, toHost: string): boolean {
  const normFrom = fromHost.toLowerCase().trim();
  const normTo = toHost.toLowerCase().trim();
  if (normFrom === normTo) return true;

  for (const entry of Object.values(BRAND_DOMAIN_REGISTRY)) {
    const fromApproved = entry.approvedDomains.some((d) => isDomainOrSubdomain(normFrom, d));
    if (fromApproved) {
      const toApproved = entry.approvedDomains.some((d) => isDomainOrSubdomain(normTo, d));
      const toAffiliated = (entry.affiliatedAuthDomains || []).some((d) => isDomainOrSubdomain(normTo, d));
      if (toApproved || toAffiliated) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Detects whether a string is a negation or non-warning statement
 * (e.g. "None observed", "No suspicious prompts", "None observed - no urgency language").
 */
export function isNegationOrNonWarning(text: string): boolean {
  if (!text || typeof text !== "string") return true;
  const t = text.trim().toLowerCase();
  if (
    t === "" ||
    t === "none" ||
    t === "n/a" ||
    t === "none observed" ||
    t === "none detected" ||
    t === "no warnings" ||
    t === "no warning signs" ||
    t === "nil" ||
    t === "null" ||
    t === "[]" ||
    t === "false"
  ) {
    return true;
  }
  if (
    /^(none\s+observed|none\s+detected|no\s+suspicious|no\s+warning|no\s+threat|no\s+urgency|no\s+credential|no\s+login|no\s+download|no\s+deceptive|no\s+apparent\s+threat)/i.test(
      t
    )
  ) {
    return true;
  }
  return false;
}

/**
 * Detects whether an item is a probe limitation / incomplete check
 * (e.g. "Lack of visible footer links", "Footer links not verified", "Inaccessible footer", "DOM certificate details could not be extracted").
 * These are limitations of the read-only probe, NOT security threats.
 */
export function isIncompleteCheckOrLimitation(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();
  return (
    /footer\s+links?/i.test(t) ||
    /dom\s+certificate/i.test(t) ||
    /inaccessible\s+footer/i.test(t) ||
    /probe\s+limitation/i.test(t) ||
    /could\s+not\s+be\s+extracted/i.test(t) ||
    /not\s+verified\s+by\s+probe/i.test(t) ||
    /dynamic\s+content\s+limitation/i.test(t)
  );
}

/**
 * Detects whether an observed text describes an ordinary fundraising or non-profit donation appeal.
 * Ordinary donation appeals (such as Wikipedia fundraising banners) use persuasive language but are NOT deceptive threats.
 */
export function isOrdinaryDonationAppeal(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();

  const isDonationRelated =
    /donat(e|ion|ions|ing)|fundrais(ing|er|ers)|charit(y|able)|non-profit\s+appeal|supporter\s+contribution/i.test(t);

  if (!isDonationRelated) return false;

  // Must not involve account compromise, password coercion, or suspension
  const isMaliciousThreat =
    /account\s+suspension|locked\s+account|verify\s+password|security\s+compromise|credential|malware|stolen/i.test(t);

  return !isMaliciousThreat;
}

/**
 * Detects whether an observed text describes evidence-backed deceptive urgency.
 * Deceptive urgency includes artificial deadlines, threats of account suspension, or coercive claims designed to elicit sensitive data.
 */
export function isDeceptiveUrgency(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();

  return (
    /account\s+will\s+be\s+suspended/i.test(t) ||
    /suspend(ed)?\s+within\s+\d+/i.test(t) ||
    /immediate(ly)?\s+verify\s+(your\s+)?account/i.test(t) ||
    /urgent\s+security\s+verification/i.test(t) ||
    /unauthorized\s+transaction\s+detected/i.test(t) ||
    /threat\s+of\s+(account\s+deletion|termination|legal\s+action)/i.test(t) ||
    /artificial\s+countdown\s+timer/i.test(t) ||
    /coercive\s+(warning|deadline)/i.test(t)
  );
}

/**
 * Detects whether a text describes an ordinary app-store link, mobile app download link,
 * or informational link rather than an active browser prompt or automatic file execution.
 */
export function isAppStoreOrInformationalDownload(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();
  return (
    /app\s*store|google\s*play|play\s*store|f-droid|microsoft\s*store/i.test(t) ||
    /download\s+(the\s+)?(mobile\s+)?app/i.test(t) ||
    /links?\s+to\s+(download|app)/i.test(t) ||
    /available\s+on\s+(ios|android|google\s*play|app\s*store)/i.test(t) ||
    /optional\s+mobile\s+app/i.test(t)
  );
}

/**
 * Detects whether a finding describes an active, direct browser download prompt or high-privilege permission request.
 */
export function isActiveDownloadOrPermissionPrompt(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();
  return (
    /automatic\s+download/i.test(t) ||
    /prompt(ed|s)?\s+(to\s+)?download\s+(executable|\.exe|\.apk|\.zip|\.dmg|\.bat|\.sh)/i.test(t) ||
    /direct\s+download\s+prompt/i.test(t) ||
    /permission\s+(dialog|prompt|request(ed)?)\s+(for\s+)?(camera|microphone|notification|geolocation|location)/i.test(t) ||
    /browser\s+permission\s+requested/i.test(t)
  );
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((x) => String(x).trim()).filter(Boolean);
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

function booleanOrStringFlag(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === "string") {
    return /^(yes|true|requested|present|observed|detected)$/i.test(value.trim());
  }
  return false;
}

function sanitizeText(value: unknown, maxLength = 500): string {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

export interface ActionPreviewOptions {
  isOfficialDomain?: boolean;
  hasImpersonation?: boolean;
  hasPhishingThreat?: boolean;
  hasCredentialWarning?: boolean;
  isExplicitLoginDestination?: boolean;
}

/**
 * Builds an Action Preview describing real-world consequences accurately,
 * distinguishing general browsing from explicit credential submission and avoiding false impersonation claims.
 */
export function generateActionPreview(
  facts: ObservedFacts,
  riskOutcome: RiskOutcome,
  claimedOrg?: string,
  destinationHost?: string,
  options?: ActionPreviewOptions
): ActionPreview {
  const riskFactors: string[] = [];
  const isOfficial = options?.isOfficialDomain ?? false;
  const hasImpersonation = options?.hasImpersonation ?? false;
  const hasPhishingThreat = options?.hasPhishingThreat ?? false;
  const hasCredentialWarning = options?.hasCredentialWarning ?? false;
  const isExplicitLogin = options?.isExplicitLoginDestination ?? false;

  // 1. Risk Factors Grounding
  if (facts.isHttp) {
    riskFactors.push("Destination uses unencrypted HTTP; data sent in transit can be intercepted.");
  }
  if (facts.hasPunycode) {
    riskFactors.push("Destination hostname uses internationalized lookalike characters (punycode).");
  }
  if (facts.hasPaymentField) {
    riskFactors.push("Destination requests financial, credit card, or payment transaction details.");
  }
  if (facts.downloadOrPermissionRequest) {
    riskFactors.push("Destination actively prompts for file downloads or elevated browser permissions.");
  }

  if (facts.hasPasswordField || facts.credentialOrPaymentRequest) {
    if (isOfficial) {
      riskFactors.push("Destination provides an authentic account sign-in option.");
    } else if (hasImpersonation || hasPhishingThreat) {
      riskFactors.push("Destination prompts for account credentials on a suspicious or impersonated domain.");
    } else {
      riskFactors.push("Destination prompts for account credentials on an unverified destination.");
    }
  }

  // 2. Proposed Action
  let proposedAction = destinationHost ? `Navigating to ${destinationHost}.` : "Navigating to this destination.";

  if (isExplicitLogin && (facts.credentialOrPaymentRequest || facts.hasPasswordField)) {
    proposedAction = `Submitting credentials on ${destinationHost || "the page"}.`;
  } else if (facts.hasPaymentField) {
    proposedAction = `Submitting payment details on ${destinationHost || "the page"}.`;
  } else if (facts.downloadOrPermissionRequest) {
    proposedAction = `Downloading or executing files prompted by ${destinationHost || "the page"}.`;
  }

  // 3. Consequence Simulation
  let consequenceIfProceed = "Routine web browsing with no special actions requested.";

  if (hasImpersonation || hasPhishingThreat) {
    // Evidence-backed impersonation or credential harvesting
    if (facts.credentialOrPaymentRequest || facts.hasPasswordField) {
      consequenceIfProceed = claimedOrg
        ? `Credentials entered may be stolen by an unauthorized third party masquerading as ${claimedOrg}. This can lead to account takeover and identity theft.`
        : "Credentials entered may be captured by a fraudulent or deceptive destination, exposing your account to unauthorized access.";
    } else {
      consequenceIfProceed = claimedOrg
        ? `This destination appears to be an unauthorized site masquerading as ${claimedOrg}. Proceeding exposes you to deceptive content.`
        : "This destination exhibits indicators of deception or impersonation. Do not proceed or disclose personal information.";
    }
  } else if (isOfficial) {
    // Authentic official domain: never claim masquerading
    if (isExplicitLogin && (facts.credentialOrPaymentRequest || facts.hasPasswordField)) {
      consequenceIfProceed = `Credentials will be submitted to the official ${claimedOrg || destinationHost} service. Ensure you intended to sign in.`;
    } else if (riskOutcome === "Suspicious" || riskOutcome === "High risk") {
      consequenceIfProceed = `You are connecting to an authentic service for ${claimedOrg || destinationHost}, but specific warnings were flagged. Review the findings before proceeding.`;
    } else {
      consequenceIfProceed = "Routine web browsing with no special actions requested.";
    }
  } else if (hasCredentialWarning) {
    // Unverified destination with credential prompts (no confirmed brand match)
    consequenceIfProceed =
      "Credentials entered may be captured by an unverified destination, exposing your account to unauthorized access.";
  } else if (facts.downloadOrPermissionRequest) {
    if (riskOutcome === "High risk" || riskOutcome === "Suspicious") {
      consequenceIfProceed = "Downloading unverified files can install unwanted software, malware, or spyware on your device.";
    } else {
      consequenceIfProceed = "A file will be saved to your device. Verify its digital signature before opening.";
    }
  } else if (riskOutcome === "Unknown") {
    consequenceIfProceed = "The destination could not be validated by independent checks. Proceed with extra caution and do not disclose sensitive details.";
  } else if (riskOutcome === "Suspicious") {
    consequenceIfProceed = "Specific warning signs were detected on this page. Review the evidence findings before taking sensitive actions.";
  } else if (riskOutcome === "High risk") {
    consequenceIfProceed = "Severe security threats were detected on this destination. Close the tab immediately.";
  }

  return {
    proposedAction,
    consequenceIfProceed,
    riskFactors,
  };
}

/**
 * Deterministic policy evaluator grounded strictly in validated evidence.
 */
export function assessInvestigation(params: {
  submittedUrl: URL;
  tinyFishResult: TinyFishExecutionResult;
}): InvestigationReport {
  const { submittedUrl, tinyFishResult } = params;
  const investigationId = `inv_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  const timestamp = new Date().toISOString();

  const structured = tinyFishResult.structuredResult;
  const rawText = tinyFishResult.rawAgentText || "";

  // 1. Destination & Redirects
  const submittedHost = submittedUrl.hostname.toLowerCase();
  let finalUrlStr: string | undefined = structured?.observed_final_url;
  let finalHost: string | undefined;
  let destinationChanged = false;
  let hasUnsafeRedirect = false;
  let unsafeRedirectReason = "";

  if (finalUrlStr) {
    try {
      const parsedFinal = new URL(finalUrlStr);
      if (parsedFinal.protocol !== "http:" && parsedFinal.protocol !== "https:") {
        finalUrlStr = undefined;
      } else {
        finalHost = parsedFinal.hostname.toLowerCase();
        destinationChanged = finalHost !== submittedHost;

        const redirectCheck = isUnsafeDestination(finalHost);
        if (redirectCheck.unsafe) {
          hasUnsafeRedirect = true;
          unsafeRedirectReason = redirectCheck.reason || "Destination redirected to a private or restricted network address.";
        }
      }
    } catch {
      finalUrlStr = undefined;
    }
  }

  const redirectChain: string[] = [submittedUrl.toString()];
  if (finalUrlStr && finalUrlStr !== submittedUrl.toString()) {
    redirectChain.push(finalUrlStr);
  }

  const observedDestination: ObservedDestination = {
    submittedUrl: submittedUrl.toString(),
    normalizedUrl: submittedUrl.toString(),
    submittedHost,
    finalUrl: finalUrlStr,
    finalHost,
    destinationChanged,
    redirectChain,
  };

  // 2. Checks performed tracking
  const checksPerformed: CheckPerformed[] = [
    {
      name: "URL & Protocol Structure",
      status: "completed",
      detail: `Validated protocol (${submittedUrl.protocol}) and hostname structure.`,
    },
    {
      name: "Private Network / SSRF Filter",
      status: "completed",
      detail: "Confirmed destination does not map to private, loopback, or metadata addresses.",
    },
    {
      name: "Read-Only Browser Investigation",
      status: tinyFishResult.success ? "completed" : "failed",
      detail: tinyFishResult.success
        ? "Remote browser inspected destination landing page in read-only mode."
        : tinyFishResult.errorMessage || "Remote browser investigation did not complete successfully.",
    },
  ];

  if (structured?.checks_performed && Array.isArray(structured.checks_performed)) {
    for (const chk of structured.checks_performed) {
      checksPerformed.push({
        name: `Browser: ${String(chk).slice(0, 60)}`,
        status: "completed",
        detail: String(chk),
      });
    }
  }

  // 3. Observed Facts Extraction (Strictly grounded in structured evidence, not raw text regex)
  const hasPunycode = submittedHost.includes("xn--");
  const isNumericIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(submittedHost) || submittedHost.includes(":");
  const isHttp = submittedUrl.protocol === "http:";

  const structuredCred = booleanOrStringFlag(structured?.credential_or_payment_request);
  const structuredLogin = booleanOrStringFlag(structured?.login_form_observed);
  const structuredPassword = booleanOrStringFlag(structured?.password_field_observed);
  const structuredPayment = booleanOrStringFlag(structured?.payment_field_observed);
  let structuredDownload = booleanOrStringFlag(structured?.download_or_permission_request);
  const appStoreLinkOnly = booleanOrStringFlag(structured?.app_store_or_informational_link_only);

  const credOrPaymentRequested = structuredCred || structuredPassword || structuredPayment;
  const hasPasswordField = structuredPassword;
  const hasPaymentField = structuredPayment;
  const formsObserved = structuredLogin || structuredPassword || structuredPayment || credOrPaymentRequested;

  // Distinguish ordinary app-store / informational links from active download prompts
  const visiblePurposeText = sanitizeText(structured?.visible_purpose);
  const overallObsText = sanitizeText(structured?.overall_observation);
  const warningsCombined = stringList(structured?.observed_warning_signs).join(" ");
  const rawEvidenceText = `${visiblePurposeText} ${overallObsText} ${warningsCombined} ${rawText}`;
  let isInformationalAppStoreLink = appStoreLinkOnly;
  if (appStoreLinkOnly) {
    structuredDownload = false;
  } else if (structuredDownload) {
    if (isAppStoreOrInformationalDownload(rawEvidenceText) && !isActiveDownloadOrPermissionPrompt(rawEvidenceText)) {
      isInformationalAppStoreLink = true;
      structuredDownload = false;
    }
  }

  const observedFacts: ObservedFacts = {
    pageTitle: sanitizeText(structured?.page_title),
    visiblePurpose: visiblePurposeText,
    credentialOrPaymentRequest: credOrPaymentRequested,
    downloadOrPermissionRequest: structuredDownload,
    formsObserved,
    hasPasswordField,
    hasPaymentField,
    hasPunycode,
    isNumericIp,
    isHttp,
  };

  // 4. Evidence Items collection
  const evidenceItems: Finding[] = [];
  const warningSigns: string[] = [];
  const missingEvidence: string[] = [];

  // Transport and host findings
  if (isHttp) {
    const item: Finding = {
      label: "Unencrypted HTTP Connection",
      detail: "The destination uses unencrypted HTTP. Data sent over this link is vulnerable to interception.",
      kind: "warning",
      provenance: "url_structure",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  if (hasPunycode) {
    const item: Finding = {
      label: "Internationalized Domain (Punycode)",
      detail: `The domain name uses punycode (${submittedHost}), which can be used to disguise deceptive look-alike characters.`,
      kind: "warning",
      provenance: "url_structure",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  if (isNumericIp) {
    const item: Finding = {
      label: "Raw IP-Literal Destination",
      detail: "The destination uses a raw IP address instead of a recognized registered domain name.",
      kind: "warning",
      provenance: "url_structure",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  if (destinationChanged && finalHost) {
    const isAffiliated = isAffiliatedRedirection(submittedHost, finalHost);
    if (isAffiliated) {
      evidenceItems.push({
        label: "Affiliated Redirection Observed",
        detail: `The destination redirected to an affiliated authentication or corporate domain (${finalHost}).`,
        kind: "neutral",
        provenance: "redirect_analysis",
      });
    } else {
      const item: Finding = {
        label: "Destination Redirect Host Mismatch",
        detail: `The final destination (${finalHost}) differs from the submitted link (${submittedHost}). Verify this redirection is expected.`,
        kind: "warning",
        provenance: "redirect_analysis",
      };
      evidenceItems.push(item);
      warningSigns.push(item.label);
    }
  }

  if (hasUnsafeRedirect && finalHost) {
    const item: Finding = {
      label: "SSRF Alert: Redirect to Restricted Address",
      detail: `The destination redirected to an internal, private, or metadata network address (${finalHost}): ${unsafeRedirectReason}`,
      kind: "warning",
      provenance: "redirect_analysis",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  // Reserved Example Domain Handling (RFC 2606)
  const isReservedExample = isReservedExampleDomain(submittedHost);
  let claimedOrg = sanitizeText(structured?.claimed_organization);

  if (isReservedExample) {
    // Example domains do not claim to represent IANA/ICANN; references are informational
    claimedOrg = "";
    evidenceItems.push({
      label: "Reserved Documentation Domain",
      detail:
        "The destination is an officially reserved example/documentation domain (RFC 2606 / RFC 6761). References to standards bodies or other organizations are informational references and do not represent corporate brand claims.",
      kind: "neutral",
      provenance: "url_structure",
    });
  }

  // Claimed Organization & Brand Registry Affiliation Evaluation
  const brandAffiliation = evaluateBrandAffiliation(claimedOrg, submittedHost);

  if (claimedOrg && !isReservedExample) {
    evidenceItems.push({
      label: "Claimed Identity",
      detail: `The page presents itself as representing: ${claimedOrg}.`,
      kind: "neutral",
      provenance: "page_content",
    });

    if (brandAffiliation.hasMismatch) {
      const mismatchItem: Finding = {
        label: "Branding vs Domain Discrepancy",
        detail:
          brandAffiliation.reason ||
          `The page claims to represent "${claimedOrg}", but the domain (${submittedHost}) does not appear affiliated with that organization.`,
        kind: "warning",
        provenance: "policy_rule",
      };
      evidenceItems.push(mismatchItem);
      warningSigns.push(mismatchItem.label);
    } else if (brandAffiliation.isOfficialDomain) {
      evidenceItems.push({
        label: "Matches Configured Brand Registry",
        detail: `The domain (${submittedHost}) matches the configured brand-domain registry for ${brandAffiliation.canonicalBrand}.`,
        kind: "positive",
        provenance: "policy_rule",
      });
    } else if (!brandAffiliation.isRegisteredBrand) {
      missingEvidence.push(`Independent third-party verification of domain ownership for claimed brand "${claimedOrg}".`);
    }
  }

  // Credential and Form Observations
  if (credOrPaymentRequested || hasPasswordField || hasPaymentField) {
    if (brandAffiliation.isOfficialDomain) {
      // Authentic sign-in form on verified official domain
      evidenceItems.push({
        label: "Authentic Sign-in Form Observed",
        detail: `The page renders an authentic authentication form on ${brandAffiliation.canonicalBrand}'s verified official domain.`,
        kind: "neutral",
        provenance: "browser_observation",
      });
      // Neutral finding: not added to warningSigns
    } else if (brandAffiliation.hasMismatch) {
      // Credential prompt on impersonated domain (phishing)
      const item: Finding = {
        label: "Credential Form on Impersonated Domain",
        detail: `The page requests login credentials for ${brandAffiliation.canonicalBrand}, but the destination domain (${submittedHost}) is not affiliated with this organization.`,
        kind: "warning",
        provenance: "policy_rule",
      };
      evidenceItems.push(item);
      warningSigns.push(item.label);
    } else {
      // Credential prompt on unverified destination
      const item: Finding = {
        label: "Credential or Payment Input Form Observed",
        detail: "The page requests login credentials, passwords, or payment information on an unverified destination.",
        kind: "warning",
        provenance: "browser_observation",
      };
      evidenceItems.push(item);
      warningSigns.push(item.label);
    }
  }

  // Informational app store link vs active download prompt
  if (isInformationalAppStoreLink) {
    evidenceItems.push({
      label: "Informational App Store Link",
      detail:
        "The page provides standard links to official mobile app stores or download pages; no automatic download or browser permission prompt was triggered.",
      kind: "neutral",
      provenance: "browser_observation",
    });
  }

  // Active file download prompt
  if (observedFacts.downloadOrPermissionRequest) {
    const item: Finding = {
      label: "Download or Permission Prompt Observed",
      detail: "The destination triggers or encourages downloading software or granting device permissions.",
      kind: "warning",
      provenance: "browser_observation",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  // Adversarial prompt injection defense
  const hasPromptInjection = PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(rawText));
  if (hasPromptInjection) {
    const injectionItem: Finding = {
      label: "Adversarial Instruction Detected in Web Content",
      detail: "The page contains text patterns attempting to manipulate AI security evaluations. The content was isolated and discounted.",
      kind: "warning",
      provenance: "policy_rule",
    };
    evidenceItems.push(injectionItem);
    warningSigns.push(injectionItem.label);
  }

  // Agent observed warning signs with Negation, Limitation, Donation & App-Store Filtering
  const agentWarnings = stringList(structured?.observed_warning_signs);
  for (const rawW of agentWarnings) {
    if (isNegationOrNonWarning(rawW)) {
      // Discard negations such as "None observed - no urgency language..."
      continue;
    }
    if (isIncompleteCheckOrLimitation(rawW)) {
      // Route probe limitations (e.g. inaccessible footer links) to missingEvidence
      if (!missingEvidence.includes(rawW)) {
        missingEvidence.push(rawW);
      }
      evidenceItems.push({
        label: "Investigation Limitation",
        detail: rawW,
        kind: "neutral",
        provenance: "browser_observation",
      });
      continue;
    }
    if (isOrdinaryDonationAppeal(rawW)) {
      // Route ordinary donation/fundraising appeals to neutral observations
      evidenceItems.push({
        label: "Fundraising / Donation Appeal Observed",
        detail: rawW,
        kind: "neutral",
        provenance: "browser_observation",
      });
      continue;
    }
    if (isAppStoreOrInformationalDownload(rawW) && !isActiveDownloadOrPermissionPrompt(rawW)) {
      // Route informational app-store links to neutral findings
      evidenceItems.push({
        label: "Informational App Store Link",
        detail: rawW,
        kind: "neutral",
        provenance: "browser_observation",
      });
      continue;
    }

    if (!warningSigns.includes(rawW)) {
      warningSigns.push(rawW);
      evidenceItems.push({
        label: "Observed Warning Sign",
        detail: rawW,
        kind: "warning",
        provenance: "browser_observation",
      });
    }
  }

  // Agent positive signals
  const agentPositives = stringList(structured?.positive_signals);
  for (const pos of agentPositives) {
    evidenceItems.push({
      label: "Positive Signal",
      detail: pos,
      kind: "positive",
      provenance: "browser_observation",
    });
  }

  // Missing evidence / unknowns
  const agentUnknowns = stringList(structured?.unknowns);
  for (const u of agentUnknowns) {
    if (!missingEvidence.includes(u)) {
      missingEvidence.push(u);
    }
  }

  // 5. Interpretations (Separated explicitly from facts)
  const modelInterpretations: ModelInterpretation[] = [];
  if (structured?.overall_observation) {
    modelInterpretations.push({
      aspect: "Investigation Summary",
      interpretation: sanitizeText(structured.overall_observation, 600),
      confidence: tinyFishResult.success ? "medium" : "low",
    });
  }

  if (claimedOrg && warningSigns.length > 0) {
    modelInterpretations.push({
      aspect: "Brand Impersonation Assessment",
      interpretation: `Brand claims ("${claimedOrg}") combined with observed warning signs suggest potential deception.`,
      confidence: "medium",
    });
  }

  // 6. Deterministic Policy Outcome Engine
  let riskOutcome: RiskOutcome;
  let threatLikelihood: ThreatLikelihood;
  let consequenceImpact: ConsequenceImpact;
  let outcomeReason: string;
  let recommendedAction: string;

  // Impact evaluation
  if (observedFacts.credentialOrPaymentRequest || observedFacts.hasPasswordField || observedFacts.hasPaymentField) {
    consequenceImpact = "High";
  } else if (observedFacts.downloadOrPermissionRequest) {
    consequenceImpact = "High";
  } else {
    consequenceImpact = "Moderate";
  }

  const allWarningText = warningSigns.join(" ").toLowerCase();
  const confirmedHighSignal = HIGH_RISK_SIGNALS.some((sig) => allWarningText.includes(sig));
  const hasSuspiciousSignal = SUSPICIOUS_SIGNALS.some((sig) => allWarningText.includes(sig));

  // Policy Rule 1: Investigation Failure or Inconclusive -> MANDATORY UNKNOWN
  if (!tinyFishResult.success || tinyFishResult.goalFailed) {
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    outcomeReason = tinyFishResult.errorMessage
      ? `The investigation could not be completed: ${tinyFishResult.errorMessage}. Missing evidence cannot be treated as safe.`
      : "The investigation ended without sufficient validated evidence. AheadGuard will never guess or declare an unverified site safe.";
    recommendedAction = "Do not proceed until you verify this destination through an independent, trusted channel.";
    missingEvidence.push("Complete live page inspection could not be finished.");
  }
  // Policy Rule 2: Confirmed High Risk Threats or SSRF Redirect Attempt
  else if (confirmedHighSignal || hasUnsafeRedirect || (hasPromptInjection && observedFacts.credentialOrPaymentRequest)) {
    riskOutcome = "High risk";
    threatLikelihood = "High";
    consequenceImpact = "Severe";
    outcomeReason = hasUnsafeRedirect
      ? `Security policy violation: Destination redirected to a restricted internal network address (${finalHost}).`
      : "Strong evidence points to high-risk deception or malicious credential targeting on this page.";
    recommendedAction = "DO NOT PROCEED. Close this tab immediately. Do not submit passwords, payment details, or download files.";
  }
  // Policy Rule 3: Suspicious Signs
  else if (warningSigns.length > 0 || hasSuspiciousSignal || hasPromptInjection) {
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    outcomeReason = `Observed ${warningSigns.length} meaningful warning sign(s) requiring caution: ${warningSigns.slice(0, 3).join("; ")}.`;
    recommendedAction = "Pause and verify. Do not enter credentials or complete financial transactions without independent confirmation.";
  }
  // Policy Rule 4: Low Observed Risk (Strict conditions: passed checks, positive signals, 0 warnings, verified domain/clean redirect)
  else if (
    (agentPositives.length >= 1 || brandAffiliation.isOfficialDomain) &&
    warningSigns.length === 0 &&
    !isHttp &&
    !hasPunycode &&
    !isNumericIp &&
    (!destinationChanged || isAffiliatedRedirection(submittedHost, finalHost || submittedHost)) &&
    !observedFacts.downloadOrPermissionRequest &&
    (!observedFacts.credentialOrPaymentRequest || brandAffiliation.isOfficialDomain)
  ) {
    riskOutcome = "Low observed risk";
    threatLikelihood = "Low";
    consequenceImpact =
      brandAffiliation.isOfficialDomain && (observedFacts.credentialOrPaymentRequest || observedFacts.hasPasswordField)
        ? "High"
        : "Low";
    outcomeReason =
      "Standard checks passed without observed warning signs. Note: this reflects the checks performed and is not a guarantee of safety.";
    recommendedAction = "Proceed with normal digital hygiene. Always confirm the domain in your address bar before entering sensitive details.";
  }
  // Policy Rule 5: Fallback to Unknown if insufficient positive proof
  else {
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    outcomeReason = "Evidence is insufficient for a conclusive verdict. No severe threats were confirmed, but positive verification is incomplete.";
    recommendedAction = "Verify the organization independently before sharing personal or sensitive information.";
    missingEvidence.push("Independent third-party verification of domain ownership.");
  }

  // 7. Action Preview Grounding
  const submittedPath = submittedUrl.pathname.toLowerCase();
  const isHomepageOrGeneralPortal =
    (submittedPath === "" || submittedPath === "/") &&
    !/^\/(login|signin|sign-in|auth)/i.test(submittedPath);

  const isDedicatedLoginPurpose =
    /^(user\s+)?(login|sign\s*in|authentication)(\s+portal|\s+page|\s+form)?$/i.test(visiblePurposeText.trim());

  const isExplicitLoginDestination =
    /^\/(login|signin|sign-in|auth|log-in|account\/login|users\/sign_in)(\/|$)/i.test(submittedPath) ||
    (!isHomepageOrGeneralPortal && isDedicatedLoginPurpose && (structuredCred || structuredPassword));

  const hasImpersonation =
    brandAffiliation.hasMismatch ||
    warningSigns.some((w) => /impersonat|masquerad|look-alike|typosquat/i.test(w));

  const hasPhishingThreat =
    confirmedHighSignal ||
    warningSigns.some((w) =>
      /phishing|credential\s+harvesting|credential\s+theft|fake\s+sign-in|cloned\s+login/i.test(w)
    );

  const hasCredentialWarning =
    warningSigns.includes("Credential or Payment Input Form Observed") ||
    warningSigns.includes("Credential Form on Impersonated Domain");

  const actionPreview = generateActionPreview(
    observedFacts,
    riskOutcome,
    claimedOrg || undefined,
    finalHost || submittedHost,
    {
      isOfficialDomain: brandAffiliation.isOfficialDomain,
      hasImpersonation,
      hasPhishingThreat,
      hasCredentialWarning,
      isExplicitLoginDestination,
    }
  );

  // 8. Explicit Transparency Limitations
  const limitations = [
    "AheadGuard provides decision support based on observed evidence; it does not replace antivirus or browser security sandboxes.",
    "Absence of detected warning signs is not a mathematical guarantee of safety.",
    "Read-only inspection cannot verify backend server storage, database handling, or internal code vulnerabilities.",
  ];

  return {
    investigationId,
    timestamp,
    originalUrl: submittedUrl.toString(),
    normalizedUrl: submittedUrl.toString(),
    observedDestination,
    claimedOrganization: claimedOrg || undefined,
    checksPerformed,
    evidenceItems,
    observedFacts,
    modelInterpretations,
    warningSigns,
    missingEvidence,
    actionPreview,
    riskOutcome,
    threatLikelihood,
    consequenceImpact,
    outcomeReason,
    recommendedAction,
    limitations,
    replayUrl: tinyFishResult.streamingUrl,
    rawAgentOutput: rawText || undefined,
    eventsCount: tinyFishResult.eventsCount,
  };
}
