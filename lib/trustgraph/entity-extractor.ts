export interface ExtractedEntity {
  type: "PHONE" | "EMAIL" | "DOMAIN" | "UPI_VPA" | "ORG_ENTITY" | "SOCIAL_HANDLE" | "QR_DESTINATION" | "CRYPTO_ADDRESS";
  value: string;
  canonicalValue: string;
  confidence: number;
}

/**
 * Normalizes phone numbers to standard E.164 format where feasible.
 */
export function normalizePhoneNumber(raw: string): string {
  const digits = raw.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) return digits;
  if (digits.length === 10) return `+91${digits}`; // Default regional mobile normalization
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  return `+${digits}`;
}

/**
 * Extracts and canonicalizes domains from raw URLs or hostnames.
 */
export function canonicalizeDomain(urlOrHost: string): string {
  try {
    const candidate = urlOrHost.includes("://") ? urlOrHost : `https://${urlOrHost}`;
    const parsed = new URL(candidate);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return urlOrHost.toLowerCase().trim();
  }
}

/**
 * Normalizes UPI IDs / Virtual Payment Addresses.
 */
export function canonicalizeUpiVpa(raw: string): string {
  return raw.trim().toLowerCase();
}

/**
 * Multi-vector entity extraction engine.
 */
export function extractEntitiesFromContent(params: {
  text?: string;
  url?: string;
  claimedOrg?: string;
  recruiter?: string;
}): ExtractedEntity[] {
  const entities: ExtractedEntity[] = [];
  const text = params.text || "";

  // 1. Domains from URL
  if (params.url) {
    const domain = canonicalizeDomain(params.url);
    if (domain) {
      entities.push({
        type: "DOMAIN",
        value: params.url,
        canonicalValue: domain,
        confidence: 1.0,
      });
    }
  }

  // 2. URLs embedded in text
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  const foundUrls = text.match(urlRegex) || [];
  for (const u of foundUrls) {
    const clean = u.replace(/[.,;:!?)]+$/, "");
    const dom = canonicalizeDomain(clean);
    if (dom && (!params.url || dom !== canonicalizeDomain(params.url))) {
      entities.push({
        type: "DOMAIN",
        value: clean,
        canonicalValue: dom,
        confidence: 0.95,
      });
    }
  }

  // 3. Phone Numbers (supports international E.164, Indian 5+5, standard 3+3+4, and 10-digit mobile)
  const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?(?:\d{5}[-.\s]?\d{5}|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b[6-9]\d{9}\b)/g;
  const foundPhones = text.match(phoneRegex) || [];
  for (const p of foundPhones) {
    const clean = p.trim();
    const digitsOnly = clean.replace(/\D/g, "");
    if (digitsOnly.length >= 10 && digitsOnly.length <= 15) {
      entities.push({
        type: "PHONE",
        value: clean,
        canonicalValue: normalizePhoneNumber(clean),
        confidence: 0.9,
      });
    }
  }

  // 4. Emails
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const foundEmails = text.match(emailRegex) || [];
  for (const em of foundEmails) {
    const clean = em.toLowerCase().trim();
    entities.push({
      type: "EMAIL",
      value: em,
      canonicalValue: clean,
      confidence: 0.98,
    });
  }

  // 5. UPI VPAs (Virtual Payment Addresses: e.g. refund.paytm@okaxis, hire.team@icici)
  const upiRegex = /\b[a-zA-Z0-9.\-_]{2,256}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|axl|upi|barodampay|postbank)\b/gi;
  const foundUpis = text.match(upiRegex) || [];
  for (const upi of foundUpis) {
    entities.push({
      type: "UPI_VPA",
      value: upi,
      canonicalValue: canonicalizeUpiVpa(upi),
      confidence: 0.99,
    });
  }

  // 6. Social Handles (@username)
  const handleRegex = /(?<=^|\s)@[A-Za-z0-9_]{3,30}\b/g;
  const foundHandles = text.match(handleRegex) || [];
  for (const h of foundHandles) {
    entities.push({
      type: "SOCIAL_HANDLE",
      value: h.trim(),
      canonicalValue: h.trim().toLowerCase(),
      confidence: 0.85,
    });
  }

  // 7. Claimed Organization
  if (params.claimedOrg && params.claimedOrg.trim().length > 1) {
    const org = params.claimedOrg.trim();
    entities.push({
      type: "ORG_ENTITY",
      value: org,
      canonicalValue: org.toLowerCase(),
      confidence: 0.95,
    });
  }

  // Deduplicate by canonicalValue + type
  const seen = new Set<string>();
  return entities.filter((item) => {
    const key = `${item.type}:${item.canonicalValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
