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
  "executable download",
  "drive-by download",
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
export const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /aheadguard\b[^\n\r]{0,40}\b(?:please\s+)?(?:declare|mark|classify|rate|treat|report|say)\b[^\n\r]{0,40}\b(?:as\s+)?(?:safe|verified|clean|trusted|low\s+observed\s+risk)\b/i,
  /aheadguard\b[^\n\r]{0,40}\b(?:bypass|override|disable|skip|whitelist|allow\s+(?:this|all|domain|site|url))\b/i,
  /\b(?:instruction\s+for|prompt\s+for)\s+aheadguard\b/i,
  /declare\s+(this\s+site\s+|destination\s+)?(low\s+observed\s+risk|safe|verified)\b/i,
  /system\s+(prompt|instruction)\s*:/i,
  /you\s+are\s+now\s+in\s+developer\s+mode/i,
  /override\s+security\s+verdict/i,
  /\b(?:dan\s+mode|jailbreak|developer\s+mode|unrestricted\s+mode)\b/i,
  /\b(?:you\s+are\s+now|operating\s+as|act\s+as)\s+(?:in\s+)?(?:bypass|unrestricted|god|admin|safety\s+auditor)\s+mode\b/i,
  /\b(?:ai\s+auditor|security\s+evaluator|system\s+admin)\s*:\s*(?:mark|rate|declare|report)\b/i,
  /\b(?:override|bypass|disable|suspend)\s+(?:all\s+)?(?:security|safety|filtering|policy|verdict|rules|guidelines)\b/i,
  /(?:<\/textarea>|<\/script>|<!--\s*END\s+(?:INSTRUCTIONS|PROMPT|SYSTEM)\s*-->)/i,
  /\b(?:Human|User|Assistant|System)\s*:\s*(?:ignore|please\s+declare|mark\s+this|override)/i,
  /\b(?:forget|reset|clear)\s+(?:all\s+)?(?:previous\s+)?(?:instructions|context|rules|guidelines)\b/i,
  /\bdo\s+not\s+(?:flag|warn|report|alert|display\s+warnings?)\b/i,
  /\bbase64\s*:\s*[A-Za-z0-9+/=]{16,}/i,
  /\b(?:zero-width|rot13|hex-encoded)\s+override\b/i,
];

export interface BrandRegistryEntry {
  canonicalName: string;
  aliases: string[];
  approvedDomains: string[];
  affiliatedAuthDomains?: string[];
  officialCareersUrl?: string;
  officialContactUrl?: string;
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
      "about.google",
    ],
    affiliatedAuthDomains: ["accounts.google.com"],
    officialCareersUrl: "https://careers.google.com/",
    officialContactUrl: "https://about.google/contact-google/",
  },
  youtube: {
    canonicalName: "YouTube",
    aliases: ["youtube", "youtube llc", "youtube video", "youtube music", "youtube - a google company"],
    approvedDomains: ["youtube.com", "youtu.be"],
    affiliatedAuthDomains: ["accounts.google.com", "google.com"],
    officialCareersUrl: "https://careers.google.com/",
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
    officialCareersUrl: "https://careers.microsoft.com/",
    officialContactUrl: "https://support.microsoft.com/",
  },
  apple: {
    canonicalName: "Apple",
    aliases: ["apple", "apple inc"],
    approvedDomains: ["apple.com", "icloud.com"],
    affiliatedAuthDomains: ["appleid.apple.com"],
    officialCareersUrl: "https://jobs.apple.com/",
    officialContactUrl: "https://support.apple.com/",
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
    officialCareersUrl: "https://www.amazon.jobs/",
    officialContactUrl: "https://www.amazon.com/gp/help/customer/display.html",
  },
  paypal: {
    canonicalName: "PayPal",
    aliases: ["paypal", "paypal inc"],
    approvedDomains: ["paypal.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://careers.pypl.com/",
    officialContactUrl: "https://www.paypal.com/smarthelp/contact-us",
  },
  meta: {
    canonicalName: "Meta",
    aliases: ["meta", "meta platforms", "facebook", "instagram", "whatsapp"],
    approvedDomains: ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "fb.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://www.metacareers.com/",
  },
  netflix: {
    canonicalName: "Netflix",
    aliases: ["netflix", "netflix inc"],
    approvedDomains: ["netflix.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://jobs.netflix.com/",
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
    approvedDomains: ["github.com"],
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
  capitalone: {
    canonicalName: "Capital One",
    aliases: ["capital one", "capitalone", "capital one bank", "capital one financial"],
    approvedDomains: ["capitalone.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://www.capitalonecareers.com/",
    officialContactUrl: "https://www.capitalone.com/contact/",
  },
  citi: {
    canonicalName: "Citigroup (Citi)",
    aliases: ["citi", "citigroup", "citibank"],
    approvedDomains: ["citigroup.com", "citi.com", "citibank.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://careers.citigroup.com/",
  },
  stripe: {
    canonicalName: "Stripe",
    aliases: ["stripe", "stripe, llc", "stripe inc"],
    approvedDomains: ["stripe.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://stripe.com/jobs",
    officialContactUrl: "https://support.stripe.com/",
  },
  venmo: {
    canonicalName: "Venmo",
    aliases: ["venmo", "venmo (service of paypal, inc.)"],
    approvedDomains: ["venmo.com"],
    affiliatedAuthDomains: [],
  },
  square: {
    canonicalName: "Square",
    aliases: ["square", "squareup", "block, inc.", "block"],
    approvedDomains: ["squareup.com", "square.com", "block.xyz"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://careers.block.xyz/",
  },
  wise: {
    canonicalName: "Wise",
    aliases: ["wise", "transferwise", "wise payments"],
    approvedDomains: ["wise.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://wise.jobs/",
    officialContactUrl: "https://wise.com/help",
  },
  gitlab: {
    canonicalName: "GitLab",
    aliases: ["gitlab", "gitlab inc"],
    approvedDomains: ["gitlab.com", "about.gitlab.com"],
    affiliatedAuthDomains: [],
  },
  docker: {
    canonicalName: "Docker",
    aliases: ["docker", "docker inc"],
    approvedDomains: ["docker.com", "hub.docker.com"],
    affiliatedAuthDomains: [],
  },
  npm: {
    canonicalName: "npm",
    aliases: ["npm", "npmjs", "npm inc"],
    approvedDomains: ["npmjs.com"],
    affiliatedAuthDomains: [],
  },
  binance: {
    canonicalName: "Binance",
    aliases: ["binance", "binance exchange", "binance holdings"],
    approvedDomains: ["binance.com", "binance.us"],
    affiliatedAuthDomains: [],
  },
  coinbase: {
    canonicalName: "Coinbase",
    aliases: ["coinbase", "coinbase inc", "coinbase global"],
    approvedDomains: ["coinbase.com"],
    affiliatedAuthDomains: [],
  },
  kraken: {
    canonicalName: "Kraken",
    aliases: ["kraken", "payward", "payward, inc."],
    approvedDomains: ["kraken.com"],
    affiliatedAuthDomains: [],
  },
  blockchain: {
    canonicalName: "Blockchain.com",
    aliases: ["blockchain", "blockchain.com", "blockchain.com, inc."],
    approvedDomains: ["blockchain.com"],
    affiliatedAuthDomains: [],
  },
  discord: {
    canonicalName: "Discord",
    aliases: ["discord", "discord inc"],
    approvedDomains: ["discord.com", "discord.gg"],
    affiliatedAuthDomains: [],
  },
  slack: {
    canonicalName: "Slack",
    aliases: ["slack", "slack technologies", "slack technologies, llc"],
    approvedDomains: ["slack.com"],
    affiliatedAuthDomains: [],
  },
  reddit: {
    canonicalName: "Reddit",
    aliases: ["reddit", "reddit inc"],
    approvedDomains: ["reddit.com"],
    affiliatedAuthDomains: [],
  },
  linkedin: {
    canonicalName: "LinkedIn",
    aliases: ["linkedin", "linkedin corporation"],
    approvedDomains: ["linkedin.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://careers.linkedin.com/",
    officialContactUrl: "https://www.linkedin.com/help",
  },
  x: {
    canonicalName: "X (Twitter)",
    aliases: ["x", "twitter", "x corp", "twitter inc"],
    approvedDomains: ["x.com", "twitter.com", "t.co"],
    affiliatedAuthDomains: [],
  },
  proton: {
    canonicalName: "Proton",
    aliases: ["proton", "proton ag", "protonmail", "proton mail"],
    approvedDomains: ["proton.me", "protonmail.com"],
    affiliatedAuthDomains: ["account.proton.me"],
  },
  dropbox: {
    canonicalName: "Dropbox",
    aliases: ["dropbox", "dropbox inc"],
    approvedDomains: ["dropbox.com"],
    affiliatedAuthDomains: [],
  },
  box: {
    canonicalName: "Box",
    aliases: ["box", "box inc", "box.com"],
    approvedDomains: ["box.com"],
    affiliatedAuthDomains: [],
  },
  ebay: {
    canonicalName: "eBay",
    aliases: ["ebay", "ebay inc"],
    approvedDomains: ["ebay.com"],
    affiliatedAuthDomains: [],
  },
  walmart: {
    canonicalName: "Walmart",
    aliases: ["walmart", "wal-mart", "walmart inc"],
    approvedDomains: ["walmart.com"],
    affiliatedAuthDomains: [],
  },
  etsy: {
    canonicalName: "Etsy",
    aliases: ["etsy", "etsy inc"],
    approvedDomains: ["etsy.com"],
    affiliatedAuthDomains: [],
  },
  usps: {
    canonicalName: "US Postal Service",
    aliases: ["usps", "united states postal service", "u.s. postal service"],
    approvedDomains: ["usps.com"],
    affiliatedAuthDomains: [],
  },
  irs: {
    canonicalName: "Internal Revenue Service",
    aliases: ["irs", "internal revenue service"],
    approvedDomains: ["irs.gov"],
    affiliatedAuthDomains: [],
  },
  cloudflare: {
    canonicalName: "Cloudflare",
    aliases: ["cloudflare", "cloudflare inc"],
    approvedDomains: ["cloudflare.com"],
    affiliatedAuthDomains: [],
  },
  openai: {
    canonicalName: "OpenAI",
    aliases: ["openai", "openai llc", "chatgpt"],
    approvedDomains: ["openai.com", "chatgpt.com"],
    affiliatedAuthDomains: ["auth0.openai.com"],
  },
  anthropic: {
    canonicalName: "Anthropic",
    aliases: ["anthropic", "anthropic pbc", "claude"],
    approvedDomains: ["anthropic.com", "claude.ai"],
    affiliatedAuthDomains: [],
  },
  vercel: {
    canonicalName: "Vercel",
    aliases: ["vercel", "vercel inc"],
    approvedDomains: ["vercel.com"],
    affiliatedAuthDomains: [],
  },
  bofa: {
    canonicalName: "Bank of America",
    aliases: ["bank of america", "bofa"],
    approvedDomains: ["bankofamerica.com", "bofa.com"],
    affiliatedAuthDomains: [],
  },
  metamask: {
    canonicalName: "MetaMask",
    aliases: ["metamask", "consensys", "metamask crypto wallet"],
    approvedDomains: ["metamask.io"],
    affiliatedAuthDomains: ["docs.metamask.io", "support.metamask.io"],
  },
  roblox: {
    canonicalName: "Roblox",
    aliases: ["roblox", "roblox corporation"],
    approvedDomains: ["roblox.com"],
    affiliatedAuthDomains: [],
  },
  xfinity: {
    canonicalName: "Xfinity",
    aliases: ["xfinity", "comcast"],
    approvedDomains: ["xfinity.com", "comcast.com"],
    affiliatedAuthDomains: [],
  },
  dpd: {
    canonicalName: "DPD",
    aliases: ["dpd", "mydpd", "dpd group"],
    approvedDomains: ["dpd.com", "dpd.co.uk", "dpd.de", "dpdgroup.com"],
    affiliatedAuthDomains: [],
  },
  dhl: {
    canonicalName: "DHL",
    aliases: ["dhl", "dhl express", "deutsche post dhl"],
    approvedDomains: ["dhl.com", "dhl.de"],
    affiliatedAuthDomains: [],
  },
  fedex: {
    canonicalName: "FedEx",
    aliases: ["fedex", "fedex corporation", "federal express"],
    approvedDomains: ["fedex.com"],
    affiliatedAuthDomains: [],
  },
  ups: {
    canonicalName: "UPS",
    aliases: ["ups", "united parcel service"],
    approvedDomains: ["ups.com"],
    affiliatedAuthDomains: [],
  },
  okta: {
    canonicalName: "Okta",
    aliases: ["okta", "okta inc"],
    approvedDomains: ["okta.com"],
    affiliatedAuthDomains: [],
  },
  scaler: {
    canonicalName: "Scaler",
    aliases: [
      "scaler",
      "scaler academy",
      "scaler by interviewbit",
      "interviewbit",
      "interviewbit technologies",
      "interviewbit technologies pte. ltd.",
      "interviewbit technologies pte ltd",
    ],
    approvedDomains: ["scaler.com", "interviewbit.com"],
    affiliatedAuthDomains: ["scaler.com", "interviewbit.com"],
    officialCareersUrl: "https://www.scaler.com/careers/",
    officialContactUrl: "https://www.scaler.com/",
  },
  leetcode: {
    canonicalName: "LeetCode",
    aliases: ["leetcode", "leetcode inc"],
    approvedDomains: ["leetcode.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://leetcode.com/jobs/",
  },
  hackerrank: {
    canonicalName: "HackerRank",
    aliases: ["hackerrank", "hackerrank inc", "interviewstreet"],
    approvedDomains: ["hackerrank.com"],
    affiliatedAuthDomains: [],
    officialCareersUrl: "https://www.hackerrank.com/careers/",
  },
  geeksforgeeks: {
    canonicalName: "GeeksforGeeks",
    aliases: ["geeksforgeeks", "gfg"],
    approvedDomains: ["geeksforgeeks.org"],
    affiliatedAuthDomains: [],
  },
  coursera: {
    canonicalName: "Coursera",
    aliases: ["coursera", "coursera inc"],
    approvedDomains: ["coursera.org"],
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
 * Checks whether a given hostname is a hosted payment profile destination (e.g. PayPal.Me).
 */
export function isHostedPaymentDestination(hostname: string): boolean {
  if (!hostname) return false;
  const h = hostname.toLowerCase().trim();
  return h === "paypal.me" || h === "www.paypal.me" || h.endsWith(".paypal.me");
}

/**
 * Checks whether a given hostname is a user-hosted content / application platform (e.g. GitHub Pages, Vercel).
 */
export function isUserHostedPlatform(hostname: string): boolean {
  if (!hostname) return false;
  const h = hostname.toLowerCase().trim();
  return (
    h === "github.io" ||
    h.endsWith(".github.io") ||
    h === "gitlab.io" ||
    h.endsWith(".gitlab.io") ||
    h === "pages.dev" ||
    h.endsWith(".pages.dev") ||
    h === "vercel.app" ||
    h.endsWith(".vercel.app") ||
    h === "now.sh" ||
    h.endsWith(".now.sh")
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
 * Known multi-part public suffixes and standard TLDs for domain boundary evaluation.
 */
export const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
  "com.au", "net.au", "org.au", "gov.au", "edu.au",
  "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
  "co.in", "net.in", "org.in", "gov.in", "edu.in",
  "com.br", "net.br", "org.br", "gov.br",
  "com.mx", "org.mx", "gob.mx", "edu.mx",
  "com.sg", "edu.sg", "gov.sg",
  "co.za", "gov.za", "edu.za",
  "com.et", "edu.et",
  "com.es", "nom.es", "org.es",
  "edu.bd", "gov.bd",
  "pages.dev", "github.io", "gitlab.io", "vercel.app", "bolt.host",
]);

/**
 * Extracts the registrable organizational domain (eTLD+1) from a hostname.
 * Examples:
 *   'about.gitlab.com' -> 'gitlab.com'
 *   'www.blockchain.com' -> 'blockchain.com'
 *   'secure.chase.com' -> 'chase.com'
 *   'service.police.uk' -> 'police.uk'
 */
export function getRegistrableDomain(hostname: string): string {
  if (!hostname || typeof hostname !== "string") return "";
  const h = hostname.toLowerCase().trim().replace(/^\[|\]$/g, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h; // IP literals

  const parts = h.split(".");
  if (parts.length <= 2) return h;

  // Check 2-part TLDs (e.g. co.uk, com.au)
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo)) {
    if (parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return h;
  }

  return parts.slice(-2).join(".");
}

/**
 * Determines whether two hostnames belong to the same registered organizational domain.
 */
export function isSameRegistrableDomain(hostA: string, hostB: string): boolean {
  if (!hostA || !hostB) return false;
  const regA = getRegistrableDomain(hostA);
  const regB = getRegistrableDomain(hostB);
  return regA !== "" && regA === regB;
}

/**
 * High-value brand identifier tokens monitored for lookalike domain impersonation.
 */
export const HIGH_VALUE_BRAND_TOKENS: Record<string, string[]> = {
  chase: ["chase"],
  bofa: ["bofa", "bankofamerica"],
  wellsfargo: ["wellsfargo"],
  citi: ["citi", "citigroup"],
  capitalone: ["capitalone"],
  paypal: ["paypal"],
  stripe: ["stripe"],
  venmo: ["venmo"],
  wise: ["wise"],
  binance: ["binance"],
  coinbase: ["coinbase"],
  kraken: ["kraken"],
  metamask: ["metamask", "metamaskwallet"],
  blockchain: ["blockchain"],
  google: ["google", "gmail"],
  microsoft: ["microsoft", "outlook", "office365"],
  apple: ["apple", "icloud"],
  amazon: ["amazon"],
  netflix: ["netflix"],
  meta: ["facebook", "instagram", "whatsapp"],
  roblox: ["roblox"],
  xfinity: ["xfinity", "xfinlty"],
  usps: ["usps"],
  irs: ["irs"],
  dpd: ["dpd", "mydpd"],
  dhl: ["dhl"],
  fedex: ["fedex"],
  ups: ["ups"],
  okta: ["okta"],
};

/**
 * Checks whether an unaffiliated hostname embeds a high-value brand keyword as a subdomain or label.
 * Enforces strict label and hyphen boundaries to avoid false matches on standard English vocabulary.
 */
export function detectLookalikeBrandInHostname(
  hostname: string,
  approvedDomains: string[] = []
): { isLookalike: boolean; brandName?: string; detail?: string } {
  if (!hostname || typeof hostname !== "string") return { isLookalike: false };
  const h = hostname.toLowerCase().trim().replace(/^\[|\]$/g, "");

  // Never flag reserved example domains, hosted payment destinations, or numeric IPs
  if (isReservedExampleDomain(h) || isHostedPaymentDestination(h) || /^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    return { isLookalike: false };
  }

  // If already approved domain for this brand or identical registrable domain
  for (const approved of approvedDomains) {
    if (isDomainOrSubdomain(h, approved) || isSameRegistrableDomain(h, approved)) {
      return { isLookalike: false };
    }
  }

  // Also check all BRAND_DOMAIN_REGISTRY approved domains
  for (const entry of Object.values(BRAND_DOMAIN_REGISTRY)) {
    if (entry.approvedDomains.some((d) => isDomainOrSubdomain(h, d) || isSameRegistrableDomain(h, d))) {
      return { isLookalike: false };
    }
  }

  const labels = h.split(".");
  // Don't check the public suffix / TLD part
  const checkLabels = labels.length > 2 ? labels.slice(0, -1) : labels.slice(0, 1);

  for (const [canonicalBrandKey, tokens] of Object.entries(HIGH_VALUE_BRAND_TOKENS)) {
    const regEntry = BRAND_DOMAIN_REGISTRY[canonicalBrandKey];
    if (regEntry && regEntry.approvedDomains.some((d) => isDomainOrSubdomain(h, d) || isSameRegistrableDomain(h, d))) {
      continue;
    }

    for (const label of checkLabels) {
      const subParts = label.split(/[-_.]/);
      for (const part of subParts) {
        const cleaned = part.replace(/^\d+|\d+$/g, "");
        if (cleaned.length === 0) continue;

        for (const token of tokens) {
          const isExact = cleaned === token;
          const isCompound =
            (cleaned.startsWith(token) || cleaned.endsWith(token)) &&
            cleaned.length >= token.length + 3 &&
            !["purchase", "metastudy", "metastable"].includes(cleaned);

          if (isExact || isCompound) {
            return {
              isLookalike: true,
              brandName: regEntry?.canonicalName || canonicalBrandKey.toUpperCase(),
              detail: `The destination domain (${h}) contains a brand identifier ("${token}") associated with ${regEntry?.canonicalName || canonicalBrandKey.toUpperCase()}, but is not an authorized corporate domain.`,
            };
          }
        }
      }
    }
  }

  return { isLookalike: false };
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
  isHostedPayment?: boolean;
  isUserHostedPlatform?: boolean;
  isThirdPartyPlatform?: boolean;
  platformName?: string;
  reason?: string;
}

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
 * Evaluates claimed organization against the destination hostname using the structured registry.
 */
export function matchesBrandAlias(text: string, alias: string): boolean {
  if (!text || !alias) return false;
  const t = text.toLowerCase().trim();
  const a = alias.toLowerCase().trim();
  if (t === a) return true;
  if (t.startsWith(a)) {
    const nextChar = t.charAt(a.length);
    if (!nextChar || /[^a-z0-9]/i.test(nextChar)) {
      return true;
    }
  }
  return false;
}

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

  // 2. Hosted payment platforms (e.g. PayPal.Me) are individual account destinations, not corporate official domains
  if (isHostedPaymentDestination(hostname)) {
    const isClaimingDifferentBrand =
      claimedOrg &&
      !/paypal/i.test(claimedOrg) &&
      Object.values(BRAND_DOMAIN_REGISTRY).some((b) =>
        b.aliases.some((a) => a === claimedOrg.toLowerCase().trim())
      );

    if (isClaimingDifferentBrand) {
      return {
        isRegisteredBrand: true,
        canonicalBrand: claimedOrg,
        isOfficialDomain: false,
        isAffiliatedDomain: false,
        hasMismatch: true,
        isHostedPayment: true,
        reason: `The page claims to represent "${claimedOrg}", but the destination (${hostname}) is a hosted payment link.`,
      };
    }

    return {
      isRegisteredBrand: false,
      canonicalBrand: "PayPal.Me",
      isOfficialDomain: false,
      isAffiliatedDomain: false,
      hasMismatch: false,
      isHostedPayment: true,
      reason: "Hosted payment link platform (paypal.me); payments are directed to individual recipient accounts.",
    };
  }

  // 3. User-hosted platform domains (e.g. *.github.io)
  if (isUserHostedPlatform(hostname)) {
    if (claimedOrg && claimedOrg.trim()) {
      const rawOrgLower = claimedOrg.toLowerCase().trim();
      const canonical = extractCanonicalBrandName(claimedOrg);
      const canonicalLower = canonical.toLowerCase().trim();

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
              matchesBrandAlias(rawOrgLower, alias) ||
              matchesBrandAlias(canonicalLower, alias)
          )
        ) {
          matchedEntry = entry;
          break;
        }
      }

      if (matchedEntry) {
        return {
          isRegisteredBrand: true,
          brandEntry: matchedEntry,
          canonicalBrand: matchedEntry.canonicalName,
          isOfficialDomain: false,
          isAffiliatedDomain: false,
          hasMismatch: true,
          isUserHostedPlatform: true,
          reason: `The page claims to represent "${matchedEntry.canonicalName}", but the domain (${hostname}) is a user-hosted site (${matchedEntry.canonicalName === "GitHub" ? "github.io" : hostname}), not the official corporate domain (${matchedEntry.approvedDomains.join(", ")}).`,
        };
      }
    }

    return {
      isRegisteredBrand: false,
      canonicalBrand: "",
      isOfficialDomain: false,
      isAffiliatedDomain: false,
      hasMismatch: false,
      isUserHostedPlatform: true,
      reason: "User-hosted platform domain; content is published by individual users and does not prove page owner identity.",
    };
  }

  // 4. Recognized Third-Party Recruitment / ATS Platforms (e.g. Greenhouse, Lever, Workday)
  // Legitimate organizations routinely host jobs on enterprise ATS platforms.
  // This is classified as a third-party platform, NOT a deceptive domain mismatch.
  const platformCheck = isRecruitmentPlatform(hostname);
  if (platformCheck.isPlatform) {
    let matchedEntry: BrandRegistryEntry | undefined;
    if (claimedOrg && claimedOrg.trim()) {
      const rawOrgLower = claimedOrg.toLowerCase().trim();
      const canonical = extractCanonicalBrandName(claimedOrg);
      const canonicalLower = canonical.toLowerCase().trim();
      for (const entry of Object.values(BRAND_DOMAIN_REGISTRY)) {
        const entryNameLower = entry.canonicalName.toLowerCase();
        if (
          entryNameLower === canonicalLower ||
          entryNameLower === rawOrgLower ||
          entry.aliases.some(
            (alias) =>
              alias === canonicalLower ||
              alias === rawOrgLower ||
              matchesBrandAlias(rawOrgLower, alias) ||
              matchesBrandAlias(canonicalLower, alias)
          )
        ) {
          matchedEntry = entry;
          break;
        }
      }
    }

    return {
      isRegisteredBrand: Boolean(matchedEntry),
      brandEntry: matchedEntry,
      canonicalBrand: matchedEntry?.canonicalName || claimedOrg || "",
      isOfficialDomain: false,
      isAffiliatedDomain: false,
      hasMismatch: false,
      isThirdPartyPlatform: true,
      platformName: platformCheck.platformName,
      reason: `Destination is hosted on ${platformCheck.platformName}, an established recruitment and job board platform.`,
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
          matchesBrandAlias(rawOrgLower, alias) ||
          matchesBrandAlias(canonicalLower, alias)
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
 * Detects whether an observed text describes ordinary commercial terms, rate-locks,
 * money-back guarantees, or standard marketing offers.
 * These are commercial assurances, NOT deceptive psychological urgency.
 */
export function isBenignCommercialTermOrGuarantee(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();

  const isCommercialGuarantee =
    /guaranteed\s+(for\s+)?\d+\s*(h|hr|hours?|m|min|minutes?|d|days?)/i.test(t) ||
    /exchange\s+rate\s+(guarantee|lock)/i.test(t) ||
    /rate\s+guaranteed/i.test(t) ||
    /price\s+(match\s+)?guarantee/i.test(t) ||
    /money[\s-]back\s+guarantee/i.test(t) ||
    /(sale|discount|deal|offer)\s+(ends|expires)\s+(in|soon)/i.test(t) ||
    /limited[\s-]time\s+(offer|deal|discount|promotion)/i.test(t) ||
    /holiday\s+(special|sale|discount|savings)/i.test(t) ||
    /free\s+shipping\s+on\s+orders/i.test(t);

  if (!isCommercialGuarantee) return false;

  // Must not involve coercive threats, account suspension, or credential requests
  const hasCoercion =
    /account\s+suspension|suspend(ed)?\s+within|immediate(ly)?\s+verify|threat\s+of|unauthorized\s+transaction|compromise|stolen|unauthorized\s+access|password|credential/i.test(t);

  return !hasCoercion;
}

/**
 * Detects whether an observed text describes an ordinary regulatory compliance notice,
 * cookie consent banner, or regional/geo-detection notification.
 */
export function isRegulatoryOrRegionalNotice(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();

  return (
    /geo[\s-]detection\s+redirect/i.test(t) ||
    /switch\s+to\s+[a-z0-9\.\-]+\s*\(\s*separate\s+entity\s*\)/i.test(t) ||
    /regional\s+(notice|switcher|redirect|portal)/i.test(t) ||
    /select\s+your\s+(country|region|language)/i.test(t) ||
    /cookie\s+(preferences?|consent|banner|policy)/i.test(t) ||
    /gdpr\s+notice/i.test(t)
  );
}

/**
 * Detects whether an investigation destination was blocked by an automated anti-bot
 * challenge, CDN security perimeter, or network-level access control.
 * These are INCOMPLETE INSPECTION conditions that mandate an Unknown verdict,
 * never a suspicious phishing finding.
 */
export function isAccessBlockedOrAntiBotChallenge(
  warningOrText: string,
  pageTitle?: string,
  visiblePurpose?: string
): boolean {
  const combined = `${warningOrText || ""} ${pageTitle || ""} ${visiblePurpose || ""}`.toLowerCase();

  return (
    /access\s+blocked\s+by\s+network\s+security/i.test(combined) ||
    /blocked\s+-\s+reddit/i.test(combined) ||
    /verify\s+you\s+are\s+human/i.test(combined) ||
    /cloudflare\s+(human\s+verification|turnstile|ray\s+id|challenge)/i.test(combined) ||
    /attention\s+required!\s*\|\s*cloudflare/i.test(combined) ||
    /just\s+a\s+moment\.\.\./i.test(combined) ||
    /ddos[\s-]guard/i.test(combined) ||
    /403\s+forbidden\s*-\s*access\s+denied/i.test(combined) ||
    /request\s+blocked\s+by\s+security\s+rules/i.test(combined) ||
    /bot\s+detection\s+(challenge|interstitial|perimeter)/i.test(combined)
  );
}

/**
 * Detects whether an observed destination is dormant, suspended, expired, or non-functional.
 * Inactive pages must not be declared Low observed risk.
 */
export function isDormantOrSuspendedPage(
  pageTitle?: string,
  visiblePurpose?: string,
  overallObservation?: string
): boolean {
  const combined = `${pageTitle || ""} ${visiblePurpose || ""} ${overallObservation || ""}`.toLowerCase();

  return (
    /сайт\s+временно\s+недоступен/i.test(combined) ||
    /site\s+temporarily\s+unavailable/i.test(combined) ||
    /account\s+suspended/i.test(combined) ||
    /domain\s+(parked|expired|parking)/i.test(combined) ||
    /this\s+domain\s+has\s+expired/i.test(combined) ||
    /suspended\s+page/i.test(combined) ||
    /hosting\s+subscription\s+expired/i.test(combined) ||
    /default\s+web\s+site\s+page/i.test(combined) ||
    /server\s+default\s+page/i.test(combined)
  );
}

/**
 * Detects whether page content discusses prompt injection, adversarial machine learning,
 * or AI security vulnerabilities in an educational, research, or documentation context.
 */
export function isEducationalOrSecurityArticle(
  pageTitle?: string,
  visiblePurpose?: string,
  rawText?: string
): boolean {
  const combined = `${pageTitle || ""} ${visiblePurpose || ""} ${rawText || ""}`.toLowerCase();
  const researchIndicators = [
    "security research",
    "vulnerability advisory",
    "owasp",
    "cve-",
    "mitre",
    "academic paper",
    "educational article",
    "prompt injection vulnerability",
    "understanding llm",
    "ai safety guidelines",
    "study on prompt injection",
    "discussing jailbreak",
    "jailbreak analysis",
    "llm security testing",
    "llm top 10",
    "prompt injection attack",
    "adversarial prompt",
    "defending against prompt injection",
    "ai red team",
    "ai red teaming",
    "prompt injection mitigation",
    "security guide",
  ];
  return researchIndicators.some((ind) => combined.includes(ind));
}

/**
 * Detects whether a text describes an ordinary app-store link, mobile/desktop app download link,
 * or informational software download button rather than an active browser prompt or automatic file execution.
 */
export function isAppStoreOrInformationalDownload(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();
  return (
    /app\s*store|google\s*play|play\s*store|f-droid|microsoft\s*store/i.test(t) ||
    /download\s+(the\s+)?(mobile\s+)?app/i.test(t) ||
    /links?\s+to\s+(download|app)/i.test(t) ||
    /available\s+on\s+(ios|android|google\s*play|app\s*store|windows|mac|linux)/i.test(t) ||
    /download\s+(for\s+)?(windows|mac|macos|linux|ios|android|desktop)/i.test(t) ||
    /download\s+(discord|slack|chrome|firefox|zoom|teams|app|client)/i.test(t) ||
    /desktop\s+(client|app)\s+download/i.test(t) ||
    /optional\s+(mobile|desktop)\s+app/i.test(t) ||
    /button\s+to\s+download/i.test(t) ||
    /standard\s+download\s+link/i.test(t)
  );
}

/**
 * Detects whether a finding describes an active, direct browser download prompt or high-privilege permission request.
 */
export function isActiveDownloadOrPermissionPrompt(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const t = text.trim().toLowerCase();

  // Filter out negative assertions ("no automatic download", "not an automatic download")
  // and agent inspection logs ("checked for automatic download")
  const cleaned = t
    .replace(/(?:no|not\s+an?|without|neither)\s+automatic(?:ally)?\s+downloads?/gi, "")
    .replace(/checked\s+for\s+automatic\s+downloads?/gi, "");

  return (
    /(?:initiates?|triggers?|prompts?|started|began)\s+(?:an?\s+)?automatic(?:ally)?\s+download/i.test(cleaned) ||
    /automatic(?:ally)?\s+(?:downloaded|downloading|downloads)\s+(?:a\s+file|executable|payload|\.exe|\.zip|\.dmg)/i.test(cleaned) ||
    /download\s+started\s+(?:without\s+user|automatically)/i.test(cleaned) ||
    /prompt(?:ed|s)?\s+(?:to\s+)?(?:save|run|execute)\s+(?:executable|\.exe|\.apk|\.zip|\.dmg|\.bat|\.sh|\.vbs|\.ps1)/i.test(cleaned) ||
    /direct\s+download\s+prompt\s+without\s+interaction/i.test(cleaned) ||
    /permission\s+(?:dialog|prompt|request(?:ed)?)\s+(?:for\s+)?(?:camera|microphone|notification|geolocation|location)/i.test(cleaned) ||
    /browser\s+permission\s+requested/i.test(cleaned) ||
    /drive-by\s+download/i.test(cleaned)
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
  isHostedPayment?: boolean;
  isUserHostedPlatform?: boolean;
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
  const isHostedPayment = options?.isHostedPayment ?? false;
  const isUserHostedPlatform = options?.isUserHostedPlatform ?? false;

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
    } else if (isHostedPayment) {
      riskFactors.push("Destination requests payment transfer details for an unverified recipient account.");
    } else {
      riskFactors.push("Destination prompts for account credentials on an unverified destination.");
    }
  } else if (isHostedPayment) {
    riskFactors.push("Destination is a hosted payment link where recipient identity requires independent confirmation.");
  }

  // 2. Proposed Action
  let proposedAction = destinationHost ? `Navigating to ${destinationHost}.` : "Navigating to this destination.";

  if (isHostedPayment && (facts.hasPaymentField || facts.credentialOrPaymentRequest)) {
    proposedAction = `Submitting payment or transfer details on ${destinationHost || "paypal.me"}.`;
  } else if (isExplicitLogin && (facts.credentialOrPaymentRequest || facts.hasPasswordField)) {
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
  } else if (isHostedPayment) {
    // Hosted payment link (e.g. PayPal.Me)
    if (facts.hasPaymentField || facts.credentialOrPaymentRequest) {
      consequenceIfProceed =
        "Payment will be processed via hosted payment link. Verify the intended recipient before confirming transfer.";
    } else {
      consequenceIfProceed =
        "Routine browsing on a hosted payment profile page. Confirm recipient details before sending funds.";
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
  } else if (isUserHostedPlatform && (facts.hasPasswordField || facts.credentialOrPaymentRequest)) {
    consequenceIfProceed =
      "Credentials entered on this user-hosted page will be received by an individual account holder, not a verified organization. Do not submit sensitive passwords.";
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
  const randSuffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID().replace(/-/g, "").slice(0, 12)
    : Math.random().toString(36).substring(2, 10);
  const investigationId = `inv_${Date.now()}_${randSuffix}`;
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

  const rawRecord = (structured || {}) as Record<string, unknown>;
  const structuredCred = booleanOrStringFlag(
    structured?.credential_or_payment_request ?? rawRecord.credential_or_payment_requested
  );
  const structuredLogin = booleanOrStringFlag(
    structured?.login_form_observed ?? rawRecord.forms_observed
  );
  const structuredPassword = booleanOrStringFlag(
    structured?.password_field_observed ?? rawRecord.has_password_field
  );
  const structuredPayment = booleanOrStringFlag(
    structured?.payment_field_observed ?? rawRecord.has_payment_field
  );
  let structuredDownload = booleanOrStringFlag(
    structured?.download_or_permission_request ?? rawRecord.download_or_permission_requested
  );
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
    const isSameDomain = isSameRegistrableDomain(submittedHost, finalHost);
    if (isAffiliated) {
      evidenceItems.push({
        label: "Affiliated Redirection Observed",
        detail: `The destination redirected to an affiliated authentication or corporate domain (${finalHost}).`,
        kind: "neutral",
        provenance: "redirect_analysis",
      });
    } else if (isSameDomain) {
      evidenceItems.push({
        label: "Intra-Domain Redirection Observed",
        detail: `The destination redirected within the same organizational domain (${finalHost}).`,
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

  // Lookalike brand domain analysis in submitted hostname
  const lookalikeCheck = detectLookalikeBrandInHostname(submittedHost);
  if (lookalikeCheck.isLookalike) {
    const item: Finding = {
      label: "Deceptive Lookalike Brand Identifier in Domain Name",
      detail: lookalikeCheck.detail || `The destination domain (${submittedHost}) appears to imitate ${lookalikeCheck.brandName}.`,
      kind: "warning",
      provenance: "policy_rule",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  // Reserved Example Domain Handling (RFC 2606) & Platform Service Classification
  const isReservedExample = isReservedExampleDomain(submittedHost);
  const isHostedPayment = isHostedPaymentDestination(submittedHost);
  const isUserHosted = isUserHostedPlatform(submittedHost);
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
  } else if (isHostedPayment) {
    evidenceItems.push({
      label: "Hosted Payment Destination",
      detail:
        "The destination is a hosted payment link (e.g. PayPal.Me). While operated on payment provider infrastructure, transactions are directed to individual or merchant recipient accounts whose identity requires independent verification.",
      kind: "neutral",
      provenance: "url_structure",
    });
    missingEvidence.push(
      "Independent verification of the specific recipient account owner on the hosted payment service."
    );
  } else if (isUserHosted) {
    evidenceItems.push({
      label: "User-Hosted Content Platform",
      detail:
        `The destination (${submittedHost}) is hosted on a user-generated content platform or cloud hosting service (e.g. GitHub Pages, Vercel). The hosting platform domain does not prove the identity of the page owner.`,
      kind: "neutral",
      provenance: "url_structure",
    });
    missingEvidence.push(
      "Independent verification of publisher identity on user-hosted platform."
    );
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
    } else if (brandAffiliation.isThirdPartyPlatform) {
      evidenceItems.push({
        label: "Recognized Third-Party Recruitment Platform",
        detail: `The destination is hosted on ${brandAffiliation.platformName || "a recognized third-party recruitment platform"}. Job vacancies hosted here require company sub-account corroboration.`,
        kind: "neutral",
        provenance: "url_structure",
      });
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
    } else if (isHostedPayment && !hasPasswordField) {
      // Hosted payment input on hosted payment destination (e.g. PayPal.Me transfer amount)
      evidenceItems.push({
        label: "Hosted Payment Form Observed",
        detail:
          "The page provides a payment transfer form on hosted platform paypal.me. Payment will be directed to the recipient account holder.",
        kind: "neutral",
        provenance: "browser_observation",
      });
      // Neutral finding: not added to warningSigns, because standard payment inputs on a payment platform are not fraud.
      // However, because isHostedPayment is true, Rule 4 will not grant Low observed risk.
      // It will resolve to Unknown because recipient identity is unverified.
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
  const textSourcesToInspect = [
    rawText,
    structured?.page_title || "",
    structured?.visible_purpose || "",
    ...(structured?.observed_warning_signs || []),
    ...(structured?.positive_signals || []),
  ].join(" \n ");
  const hasPromptInjection = PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(textSourcesToInspect));
  let isPromptInjectionWarning = false;

  if (hasPromptInjection) {
    const isEducational = isEducationalOrSecurityArticle(
      observedFacts.pageTitle,
      observedFacts.visiblePurpose,
      textSourcesToInspect
    );
    const isDirectAgentAttack = /\baheadguard\b[^\n\r]{0,40}\b(?:please\s+)?(?:declare|mark|classify|rate|treat|report|say|bypass|override|disable)\b/i.test(
      textSourcesToInspect
    );

    if (
      isEducational &&
      !isDirectAgentAttack &&
      !observedFacts.credentialOrPaymentRequest &&
      !observedFacts.hasPasswordField &&
      !observedFacts.downloadOrPermissionRequest
    ) {
      // Educational security paper or article quoting injection patterns for research: emit neutral informational observation
      evidenceItems.push({
        label: "Security Topic: Prompt Injection Mentioned",
        detail:
          "The destination discusses or references AI prompt injection concepts in an educational or research context. No active manipulation directed at AheadGuard was observed.",
        kind: "neutral",
        provenance: "browser_observation",
        evidenceNature: "direct_observation",
        sourceType: "observed_destination",
        sourceUrl: finalUrlStr || submittedUrl.toString(),
        accessible: !structured?.access_blocked,
      });
    } else {
      isPromptInjectionWarning = true;
      const injectionItem: Finding = {
        label: "Adversarial Instruction Detected in Web Content",
        detail:
          "The page contains text patterns attempting to manipulate AI security evaluations. The content was isolated and discounted.",
        kind: "warning",
        provenance: "policy_rule",
        evidenceNature: "derived_policy_rule",
        sourceType: "heuristic_rule",
        rationale: "Matches adversarial bypass or prompt injection patterns in web content.",
      };
      evidenceItems.push(injectionItem);
      warningSigns.push(injectionItem.label);
    }
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
    if (isBenignCommercialTermOrGuarantee(rawW)) {
      // Route benign commercial rate locks, guarantees, or standard marketing offers to neutral findings
      evidenceItems.push({
        label: "Commercial Term / Guarantee Observed",
        detail: rawW,
        kind: "neutral",
        provenance: "browser_observation",
      });
      continue;
    }
    if (isRegulatoryOrRegionalNotice(rawW)) {
      // Route regulatory geo-ip notices and cookie preference modals to neutral findings
      evidenceItems.push({
        label: "Regional / Compliance Notice Observed",
        detail: rawW,
        kind: "neutral",
        provenance: "browser_observation",
      });
      continue;
    }
    if (isAccessBlockedOrAntiBotChallenge(rawW, observedFacts.pageTitle, observedFacts.visiblePurpose)) {
      // Route anti-bot challenges and network blocking interstitials to limitations rather than threats
      if (!missingEvidence.includes(rawW)) {
        missingEvidence.push(rawW);
      }
      evidenceItems.push({
        label: "Access Blocked / Anti-Bot Challenge",
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
  const limitations: string[] = [
    "AheadGuard provides decision support based on observed evidence; it does not replace antivirus or browser security sandboxes.",
    "Absence of detected warning signs is not a mathematical guarantee of safety.",
    "Read-only inspection cannot verify backend server storage, database handling, or internal code vulnerabilities.",
  ];

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

  const hasAntiBotChallenge = isAccessBlockedOrAntiBotChallenge(
    warningSigns.join(" ") + " " + rawText,
    observedFacts.pageTitle,
    observedFacts.visiblePurpose
  );
  const isDormantPage = isDormantOrSuspendedPage(
    observedFacts.pageTitle,
    observedFacts.visiblePurpose,
    structured?.overall_observation
  );

  const hasIndependentUrlThreat =
    hasUnsafeRedirect ||
    confirmedHighSignal ||
    isNumericIp ||
    hasPunycode ||
    warningSigns.some((w) =>
      /lookalike|punycode|numeric\s+ip|unencrypted\s+http|domain\s+discrepancy/i.test(w)
    );

  const hasConfirmedSevereThreat =
    confirmedHighSignal ||
    hasUnsafeRedirect ||
    Boolean(structured?.automatic_download_observed) ||
    warningSigns.includes("Credential Form on Impersonated Domain") ||
    (warningSigns.some((w) => w.includes("Lookalike")) && (observedFacts.credentialOrPaymentRequest || observedFacts.hasPasswordField)) ||
    ((allWarningText.includes("requests otp") || allWarningText.includes("requests 2fa")) && (observedFacts.credentialOrPaymentRequest || observedFacts.hasPasswordField)) ||
    (isPromptInjectionWarning && (observedFacts.credentialOrPaymentRequest || observedFacts.hasPasswordField)) ||
    (hasPunycode && (observedFacts.credentialOrPaymentRequest || observedFacts.hasPasswordField));

  // Policy Rule: Confirmed Severe Threats & High-Risk Policy Violations
  // Precedence Rule: A verified severe threat (e.g. SSRF redirect to cloud metadata/private IP,
  // credential theft on impersonated domain, or automated drive-by download) must NEVER be suppressed
  // or downgraded to "Unknown" merely because the external crawler terminated, timed out, or encountered an error.
  if (hasConfirmedSevereThreat) {
    riskOutcome = "High risk";
    threatLikelihood = "High";
    consequenceImpact = "Severe";
    outcomeReason = hasUnsafeRedirect
      ? `Security policy violation: Destination redirected to a restricted internal network address (${finalHost}).`
      : "Strong evidence points to high-risk deception or malicious credential targeting on this page.";
    recommendedAction = "DO NOT PROCEED. Close this tab immediately. Do not submit passwords, payment details, or download files.";
    if (!tinyFishResult.success || tinyFishResult.goalFailed) {
      limitations.push("Crawler stream terminated with an error, but severe threat indicators were confirmed prior to termination.");
    }
  }
  // Policy Rule 1: Investigation Failure or Inconclusive (when no severe threat is confirmed) -> MANDATORY UNKNOWN
  else if (!tinyFishResult.success || tinyFishResult.goalFailed) {
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    outcomeReason = tinyFishResult.errorMessage
      ? `The investigation could not be completed: ${tinyFishResult.errorMessage}. Missing evidence cannot be treated as safe.`
      : "The investigation ended without sufficient validated evidence. AheadGuard will never guess or declare an unverified site safe.";
    recommendedAction = "Do not proceed until you verify this destination through an independent, trusted channel.";
    missingEvidence.push("Complete live page inspection could not be finished.");
  }
  // Policy Rule 1b: Access Blocked by Anti-Bot Perimeter or Incomplete Page Inspection
  // If the destination URL itself exhibits definitive threat markers (e.g. lookalike brand, unencrypted HTTP, IP host),
  // those threats take precedence over the anti-bot interstitial.
  // If the destination is an officially verified brand domain with clean signals, the anti-bot challenge
  // is recognized as standard defensive bot protection by the verified provider.
  else if (hasAntiBotChallenge && !hasIndependentUrlThreat) {
    if (
      brandAffiliation.isOfficialDomain &&
      warningSigns.length === 0 &&
      !isHttp &&
      !hasPunycode &&
      !isNumericIp &&
      (!destinationChanged ||
        isAffiliatedRedirection(submittedHost, finalHost || submittedHost) ||
        isSameRegistrableDomain(submittedHost, finalHost || submittedHost))
    ) {
      evidenceItems.push({
        label: "Official Brand Anti-Bot Security Perimeter",
        detail: `The destination is confirmed as ${brandAffiliation.canonicalBrand}'s verified official domain (${submittedHost}). The observed anti-bot security challenge is standard bot protection operated by this service.`,
        kind: "positive",
        provenance: "policy_rule",
      });
      riskOutcome = "Low observed risk";
      threatLikelihood = "Low";
      consequenceImpact = "Low";
      outcomeReason = `Verified official domain for ${brandAffiliation.canonicalBrand}. Anti-bot challenges encountered are standard security perimeters operated by this service.`;
      recommendedAction = `Routine web browsing on ${brandAffiliation.canonicalBrand}'s verified domain.`;
    } else {
      riskOutcome = "Unknown";
      threatLikelihood = "Uncertain";
      outcomeReason =
        "The destination page could not be inspected because access was blocked by an automated anti-bot security challenge or network perimeter. Missing evidence cannot be treated as safe.";
      recommendedAction =
        "The destination could not be inspected due to automated security barriers. Visit only if you independently know and trust this domain.";
      missingEvidence.push("Complete live page inspection could not be completed (access blocked by anti-bot challenge).");
    }
  }
  // Policy Rule 1c: Dormant, Parked, or Suspended Placeholder Destination -> MANDATORY UNKNOWN
  else if (isDormantPage) {
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    outcomeReason =
      "The destination page appears dormant, suspended, or temporarily unavailable. Inactive placeholder pages cannot be verified as safe.";
    recommendedAction =
      "The destination service is currently inactive or suspended. Do not attempt to submit information until normal service is verified.";
    missingEvidence.push("Active operating service could not be verified (site is dormant/suspended).");
  }
  // Policy Rule 3: Suspicious Signs
  else if (warningSigns.length > 0 || hasSuspiciousSignal || isPromptInjectionWarning) {
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    outcomeReason = `Observed ${warningSigns.length} meaningful warning sign(s) requiring caution: ${warningSigns.slice(0, 3).join("; ")}.`;
    recommendedAction = "Pause and verify. Do not enter credentials or complete financial transactions without independent confirmation.";
  }
  // Policy Rule 4: Low Observed Risk
  // Strictly requires passed checks, positive signals, 0 warning signs, clean transport/redirection,
  // and no unverified high-consequence prompts (credentials, payments, or downloads).
  // Critical identity verification cannot be bypassed by positive signals alone when that verification
  // is necessary for the action being assessed (e.g. hosted payment destinations like PayPal.Me where
  // recipient identity is unverified).
  // For ordinary informational content (including benign user-hosted content without credential/payment prompts),
  // positive signals and the absence of deceptive indicators justify Low observed risk.
  else if (
    (agentPositives.length >= 1 || brandAffiliation.isOfficialDomain) &&
    warningSigns.length === 0 &&
    !isHttp &&
    !hasPunycode &&
    !isNumericIp &&
    (!destinationChanged ||
      isAffiliatedRedirection(submittedHost, finalHost || submittedHost) ||
      isSameRegistrableDomain(submittedHost, finalHost || submittedHost)) &&
    !observedFacts.downloadOrPermissionRequest &&
    (!observedFacts.credentialOrPaymentRequest || brandAffiliation.isOfficialDomain) &&
    (!observedFacts.hasPasswordField || brandAffiliation.isOfficialDomain) &&
    (!observedFacts.hasPaymentField || brandAffiliation.isOfficialDomain) &&
    !isHostedPayment &&
    !hasAntiBotChallenge &&
    !isDormantPage
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
  // Policy Rule 5: Fallback to Unknown if insufficient positive proof or unresolved critical verification
  else {
    riskOutcome = "Unknown";
    threatLikelihood = "Uncertain";
    if (isHostedPayment) {
      outcomeReason =
        "The destination is a hosted payment link (paypal.me) where the recipient identity has not been independently verified. Positive platform signals do not substitute for recipient verification.";
      recommendedAction =
        "Verify the recipient's identity through an independent, trusted channel before transferring funds.";
    } else {
      outcomeReason =
        "Evidence is insufficient for a conclusive verdict. No severe threats were confirmed, but positive verification is incomplete.";
      recommendedAction =
        "Verify the organization independently before sharing personal or sensitive information.";
      missingEvidence.push("Independent third-party verification of domain ownership.");
    }
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
      isHostedPayment,
      isUserHostedPlatform: isUserHosted,
    }
  );

  // 8. Backfill and normalize structured evidence provenance on all findings
  for (let i = 0; i < evidenceItems.length; i++) {
    const f = evidenceItems[i];
    if (!f.id) {
      f.id = `finding-${i + 1}-${f.label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    }
    if (!f.evidenceNature) {
      if (f.provenance === "policy_rule") {
        f.evidenceNature = "derived_policy_rule";
      } else if (f.provenance === "browser_observation" || f.provenance === "redirect_analysis" || f.provenance === "url_structure") {
        f.evidenceNature = "direct_observation";
      } else {
        f.evidenceNature = "user_input_assertion";
      }
    }
    if (!f.sourceType) {
      f.sourceType =
        f.provenance === "url_structure"
          ? "submitted_url"
          : f.provenance === "redirect_analysis"
          ? "observed_destination"
          : f.provenance === "policy_rule"
          ? "heuristic_rule"
          : "observed_destination";
    }
    // Only set sourceUrl if this finding was directly extracted from an external URL.
    // Policy-derived findings and user prose assertions do NOT fabricate a web source URL.
    if (!f.sourceUrl) {
      if (f.provenance === "browser_observation" || f.provenance === "redirect_analysis") {
        f.sourceUrl = finalUrlStr || submittedUrl.toString();
      } else if (f.provenance === "url_structure") {
        f.sourceUrl = submittedUrl.toString();
      }
    }
    // Only set observedAt if this was an actual external observation provided by the crawler
    // Does NOT fabricate report generation timestamp as observation timestamp
    if (!f.observedAt && (f.provenance === "browser_observation" || f.provenance === "redirect_analysis")) {
      if (tinyFishResult.observedAt) {
        f.observedAt = tinyFishResult.observedAt;
      }
    }
    // accessible boolean: Only meaningful for actual probed network endpoints
    if (f.accessible === undefined && f.sourceUrl && (f.provenance === "browser_observation" || f.provenance === "redirect_analysis")) {
      f.accessible = !structured?.access_blocked && !tinyFishResult.goalFailed;
    }
  }

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
