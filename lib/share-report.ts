import { InvestigationReport } from "./types";
import { redactSensitivePii } from "./message-intelligence";

const SENSITIVE_PARAM_KEYS = [
  "token",
  "auth",
  "session",
  "key",
  "secret",
  "sig",
  "signature",
  "password",
  "passwd",
  "pwd",
  "otp",
  "code",
  "jwt",
  "id_token",
  "access_token",
  "refresh_token",
  "api_key",
  "apikey",
  "email",
  "user",
  "username",
  "uid",
  "account",
  "acct",
  "pin",
  "credential",
  "private",
  "phone",
  "mobile",
  "card",
  "pan",
  "aadhaar",
  "ssn",
];

function isSensitiveKey(key: string): boolean {
  const k = key.toLowerCase();
  return SENSITIVE_PARAM_KEYS.some((p) => k.includes(p));
}

function containsSensitiveValue(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  // Emails
  if (/@\w+[\.\w+]+/.test(value)) return true;
  // JWT tokens (starts with eyJ)
  if (/^eyJ[A-Za-z0-9_-]{10,}/.test(value)) return true;
  // Credit cards or long digit sequences (12+ digits)
  if (/\b\d{12,19}\b/.test(value)) return true;
  // Obvious secret prefixes
  if (/^(?:sk_live|sk_test|pk_live|ghp_|tf_live|AIza|Bearer\s)/i.test(value)) return true;
  return false;
}

/**
 * Strips sensitive tracking tokens, session IDs, authentication parameters,
 * embedded credentials, and secret hash fragments from URLs.
 */
export function sanitizeUrlForSharing(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== "string") return "";

  try {
    const parsed = new URL(rawUrl);

    // 1. Strip embedded HTTP basic/digest credentials (e.g. user:pass@host)
    parsed.username = "";
    parsed.password = "";

    // 2. Strip sensitive query parameters
    for (const key of Array.from(parsed.searchParams.keys())) {
      const val = parsed.searchParams.get(key) || "";
      if (isSensitiveKey(key) || containsSensitiveValue(val)) {
        parsed.searchParams.delete(key);
      }
    }

    // 3. Strip sensitive fragments (e.g. #access_token=... or #id_token=... or #secret)
    if (parsed.hash) {
      const hashContent = parsed.hash.startsWith("#") ? parsed.hash.slice(1) : parsed.hash;
      if (hashContent.includes("=") || hashContent.includes("&")) {
        try {
          const hashParams = new URLSearchParams(hashContent);
          for (const key of Array.from(hashParams.keys())) {
            const val = hashParams.get(key) || "";
            if (isSensitiveKey(key) || containsSensitiveValue(val)) {
              hashParams.delete(key);
            }
          }
          const remaining = hashParams.toString();
          parsed.hash = remaining ? `#${remaining}` : "";
        } catch {
          if (isSensitiveKey(hashContent) || containsSensitiveValue(hashContent)) {
            parsed.hash = "";
          }
        }
      } else if (isSensitiveKey(hashContent) || containsSensitiveValue(hashContent)) {
        parsed.hash = "";
      }
    }

    return parsed.toString();
  } catch {
    // If URL parsing fails, apply regex-based query parameter and fragment stripping
    let sanitized = rawUrl;
    // Strip sensitive query params: ?token=... or &key=...
    sanitized = sanitized.replace(/([?&])(?:token|auth|session|key|secret|sig|password|pwd|otp|code|jwt|access_token|refresh_token|api_key|email)=[^&\s#]+/gi, "$1[REDACTED]");
    // Clean up empty params
    sanitized = sanitized.replace(/[?&]\[REDACTED\]/g, "");
    // Strip secret hash fragments
    if (/#.*(?:access_token|id_token|session|token|auth|secret|key|pwd|password|otp)/i.test(sanitized)) {
      sanitized = sanitized.replace(/#.*$/, "");
    }
    return redactSensitivePii(sanitized).redactedText;
  }
}

/**
 * Sanitizes an arbitrary text string by masking emails, phone numbers, government IDs,
 * payment cards, credentials, and OTPs.
 */
function sanitizeText(text: string | undefined): string {
  if (!text || typeof text !== "string") return text || "";
  return redactSensitivePii(text).redactedText;
}

/**
 * Produces a sanitized, privacy-safe version of an InvestigationReport suitable for sharing,
 * clipboard copying, JSON export, and PDF printing without mutating the input report.
 */
export function createShareableReport(report: InvestigationReport): InvestigationReport {
  if (!report) return report;

  // Deep clone to guarantee the original on-screen report in memory is NEVER mutated
  const r: InvestigationReport = JSON.parse(JSON.stringify(report));

  // 1. Sanitize Top-Level URLs
  r.originalUrl = sanitizeUrlForSharing(r.originalUrl);
  r.normalizedUrl = sanitizeUrlForSharing(r.normalizedUrl);
  if (r.replayUrl) {
    r.replayUrl = sanitizeUrlForSharing(r.replayUrl);
  }

  // 2. Sanitize Destination Object
  if (r.observedDestination) {
    r.observedDestination.submittedUrl = sanitizeUrlForSharing(r.observedDestination.submittedUrl);
    r.observedDestination.normalizedUrl = sanitizeUrlForSharing(r.observedDestination.normalizedUrl);
    if (r.observedDestination.finalUrl) {
      r.observedDestination.finalUrl = sanitizeUrlForSharing(r.observedDestination.finalUrl);
    }
    if (Array.isArray(r.observedDestination.redirectChain)) {
      r.observedDestination.redirectChain = r.observedDestination.redirectChain.map(sanitizeUrlForSharing);
    }
    r.observedDestination.submittedHost = sanitizeText(r.observedDestination.submittedHost);
    if (r.observedDestination.finalHost) {
      r.observedDestination.finalHost = sanitizeText(r.observedDestination.finalHost);
    }
  }

  // 3. Sanitize Top-Level Text & Findings
  r.isDemo = report.isDemo === true;
  r.demoScenarioId = report.demoScenarioId;
  r.demoDisclaimer = report.demoDisclaimer ? sanitizeText(report.demoDisclaimer) : undefined;
  r.claimedOrganization = r.claimedOrganization ? sanitizeText(r.claimedOrganization) : undefined;
  r.outcomeReason = sanitizeText(r.outcomeReason);
  r.recommendedAction = sanitizeText(r.recommendedAction);
  r.warningSigns = (r.warningSigns || []).map(sanitizeText);
  r.missingEvidence = (r.missingEvidence || []).map(sanitizeText);
  r.limitations = (r.limitations || []).map(sanitizeText);

  if (Array.isArray(r.checksPerformed)) {
    r.checksPerformed = r.checksPerformed.map((c) => ({
      name: sanitizeText(c.name),
      status: c.status,
      detail: sanitizeText(c.detail),
    }));
  }

  if (Array.isArray(r.evidenceItems)) {
    r.evidenceItems = r.evidenceItems.map((e) => ({
      label: sanitizeText(e.label),
      detail: sanitizeText(e.detail),
      kind: e.kind,
      provenance: e.provenance,
    }));
  }

  if (r.observedFacts) {
    r.observedFacts.pageTitle = r.observedFacts.pageTitle ? sanitizeText(r.observedFacts.pageTitle) : undefined;
    r.observedFacts.visiblePurpose = r.observedFacts.visiblePurpose ? sanitizeText(r.observedFacts.visiblePurpose) : undefined;
  }

  if (Array.isArray(r.modelInterpretations)) {
    r.modelInterpretations = r.modelInterpretations.map((m) => ({
      aspect: sanitizeText(m.aspect),
      interpretation: sanitizeText(m.interpretation),
      confidence: m.confidence,
    }));
  }

  if (r.actionPreview) {
    r.actionPreview.proposedAction = sanitizeText(r.actionPreview.proposedAction);
    r.actionPreview.consequenceIfProceed = sanitizeText(r.actionPreview.consequenceIfProceed);
    r.actionPreview.riskFactors = (r.actionPreview.riskFactors || []).map(sanitizeText);
  }

  if (r.rawAgentOutput) {
    r.rawAgentOutput = sanitizeText(r.rawAgentOutput);
  }

  // 4. Sanitize Top-Level Extracted URLs
  if (Array.isArray(r.extractedUrls)) {
    r.extractedUrls = r.extractedUrls.map(sanitizeUrlForSharing);
  }
  if (r.selectedTargetUrl) {
    r.selectedTargetUrl = sanitizeUrlForSharing(r.selectedTargetUrl);
  }

  // 5. Sanitize Scam Intelligence Block
  if (r.scamIntelligence) {
    const s = r.scamIntelligence;

    s.messageExcerpt = s.messageExcerpt ? sanitizeText(s.messageExcerpt) : undefined;
    s.extractedUrls = (s.extractedUrls || []).map(sanitizeUrlForSharing);
    if (s.selectedTargetUrl) {
      s.selectedTargetUrl = sanitizeUrlForSharing(s.selectedTargetUrl);
    }

    // Company Identity
    if (s.companyIdentity) {
      const ci = s.companyIdentity;
      ci.claimedOrganization = ci.claimedOrganization ? sanitizeText(ci.claimedOrganization) : undefined;
      ci.destinationHost = ci.destinationHost ? sanitizeText(ci.destinationHost) : undefined;
      ci.explanation = sanitizeText(ci.explanation);
      if (ci.officialCareersUrl) {
        ci.officialCareersUrl = sanitizeUrlForSharing(ci.officialCareersUrl);
      }
      if (ci.officialContactUrl) {
        ci.officialContactUrl = sanitizeUrlForSharing(ci.officialContactUrl);
      }
      if (Array.isArray(ci.evidenceSources)) {
        ci.evidenceSources = ci.evidenceSources.map((src) => ({
          title: sanitizeText(src.title),
          url: sanitizeUrlForSharing(src.url),
          sourceType: src.sourceType,
          retrievedAt: src.retrievedAt,
          snippet: src.snippet ? sanitizeText(src.snippet) : undefined,
        }));
      }
    }

    // Job Verification
    if (s.jobVerification) {
      const jv = s.jobVerification;
      jv.claimedRole = jv.claimedRole ? sanitizeText(jv.claimedRole) : undefined;
      jv.claimedEmployer = jv.claimedEmployer ? sanitizeText(jv.claimedEmployer) : undefined;
      jv.claimedLocation = jv.claimedLocation ? sanitizeText(jv.claimedLocation) : undefined;
      jv.claimedCompensation = jv.claimedCompensation ? sanitizeText(jv.claimedCompensation) : undefined;
      jv.recruiterContact = jv.recruiterContact ? sanitizeText(jv.recruiterContact) : undefined;
      jv.explanation = sanitizeText(jv.explanation);
      jv.limitations = sanitizeText(jv.limitations);
      if (jv.matchedListingUrl) {
        jv.matchedListingUrl = sanitizeUrlForSharing(jv.matchedListingUrl);
      }
      if (Array.isArray(jv.checkedSources)) {
        jv.checkedSources = jv.checkedSources.map((src) => ({
          title: sanitizeText(src.title),
          url: sanitizeUrlForSharing(src.url),
          sourceType: src.sourceType,
          retrievedAt: src.retrievedAt,
          snippet: src.snippet ? sanitizeText(src.snippet) : undefined,
        }));
      }
    }

    // Recruitment Fee Warning
    if (s.recruitmentFeeWarning) {
      s.recruitmentFeeWarning.quotedText = sanitizeText(s.recruitmentFeeWarning.quotedText);
      s.recruitmentFeeWarning.explanation = sanitizeText(s.recruitmentFeeWarning.explanation);
    }

    // Payment Risks
    if (Array.isArray(s.paymentRisks)) {
      s.paymentRisks = s.paymentRisks.map((pr) => ({
        id: pr.id,
        paymentType: pr.paymentType,
        quotedText: sanitizeText(pr.quotedText),
        claimedRecipient: pr.claimedRecipient ? sanitizeText(pr.claimedRecipient) : undefined,
        cautionReason: sanitizeText(pr.cautionReason),
        destinationInvestigated: pr.destinationInvestigated,
        evidenceSummary: sanitizeText(pr.evidenceSummary),
        recommendedVerificationStep: sanitizeText(pr.recommendedVerificationStep),
      }));
    }

    // Sensitive Data Requests
    if (Array.isArray(s.sensitiveDataRequests)) {
      s.sensitiveDataRequests = s.sensitiveDataRequests.map((sd) => ({
        id: sd.id,
        dataCategory: sd.dataCategory,
        source: sd.source,
        quotedText: sd.quotedText ? sanitizeText(sd.quotedText) : undefined,
        riskExplanation: sanitizeText(sd.riskExplanation),
        isDestinationVerified: sd.isDestinationVerified,
      }));
    }

    // Claim Records
    if (Array.isArray(s.claims)) {
      s.claims = s.claims.map((c) => ({
        id: c.id,
        category: c.category,
        claimText: sanitizeText(c.claimText),
        claimedOrganization: c.claimedOrganization ? sanitizeText(c.claimedOrganization) : undefined,
        evaluation: c.evaluation,
        explanation: sanitizeText(c.explanation),
        sourceUrl: c.sourceUrl ? sanitizeUrlForSharing(c.sourceUrl) : undefined,
        sourceType: c.sourceType,
        provenance: c.provenance,
        retrievedAt: c.retrievedAt,
        limitations: c.limitations ? sanitizeText(c.limitations) : undefined,
        supportingSources: Array.isArray(c.supportingSources)
          ? c.supportingSources.map((src) => ({
              title: sanitizeText(src.title),
              url: sanitizeUrlForSharing(src.url),
              sourceType: src.sourceType,
              retrievedAt: src.retrievedAt,
              snippet: src.snippet ? sanitizeText(src.snippet) : undefined,
            }))
          : undefined,
      }));
    }

    // Independent Verification Routes
    if (Array.isArray(s.independentVerificationRoutes)) {
      s.independentVerificationRoutes = s.independentVerificationRoutes.map((iv) => ({
        routeType: iv.routeType,
        title: sanitizeText(iv.title),
        url: iv.url ? sanitizeUrlForSharing(iv.url) : undefined,
        isIndependentlyEstablished: iv.isIndependentlyEstablished,
        relevanceExplanation: sanitizeText(iv.relevanceExplanation),
        verifiableClaims: (iv.verifiableClaims || []).map(sanitizeText),
        limitations: sanitizeText(iv.limitations),
      }));
    }

    // Disclosure & Sanitizer Scope Notice
    s.disclaimer =
      "Sanitized Export Notice: AheadGuard removes sensitive URL parameters (tokens, session IDs, keys), strips secret URL fragments, and masks common personal identifiers (emails, phone numbers, government IDs, card numbers, passwords, OTPs). Automatic redaction minimizes data exposure, but users must confirm that unformatted or contextual secrets are not shared.";
  }

  return r;
}

/**
 * Generates clean, formatted Markdown of the investigation report for copying or sharing.
 * Always formats from the sanitized export object.
 */
export function formatReportMarkdown(report: InvestigationReport): string {
  const r = createShareableReport(report);
  const lines: string[] = [];

  if (r.isDemo) {
    lines.push(`> ⚠️ **DEMO DATA — NOT A LIVE INVESTIGATION**`);
    lines.push(`> ${r.demoDisclaimer || "This illustrative report was generated from offline demonstration data for testing and evaluation purposes. No external network request or live inspection was performed."}`);
    lines.push(``);
  }

  lines.push(`# AheadGuard AI — Trust & Verification Report`);
  lines.push(`**Date & Time:** ${r.timestamp}`);
  lines.push(`**Investigation ID:** \`${r.investigationId}\``);
  lines.push(`**Destination:** ${r.observedDestination.finalHost || r.observedDestination.submittedHost}`);
  lines.push(`**Target URL:** ${r.observedDestination.finalUrl || r.originalUrl}`);
  lines.push(`**Overall Risk Outcome:** **${r.riskOutcome.toUpperCase()}** (Threat: ${r.threatLikelihood}, Consequence: ${r.consequenceImpact})`);
  lines.push(`**Outcome Reason:** ${r.outcomeReason}`);
  lines.push(`**Recommended Action:** ${r.recommendedAction}`);
  lines.push(``);

  if (r.scamIntelligence) {
    const intel = r.scamIntelligence;
    lines.push(`## Digital Trust & Scam Intelligence`);
    lines.push(`- **Company Identity Status:** **${intel.companyIdentity.status}**`);
    lines.push(`  * ${intel.companyIdentity.explanation}`);

    if (intel.jobVerification) {
      lines.push(`- **Job/Internship Listing Status:** **${intel.jobVerification.status}**`);
      lines.push(`  * ${intel.jobVerification.explanation}`);
    }

    if (intel.recruitmentFeeWarning?.detected) {
      lines.push(``);
      lines.push(`### ⚠️ Recruitment Fee Warning`);
      lines.push(`> "${intel.recruitmentFeeWarning.quotedText}"`);
      lines.push(`*${intel.recruitmentFeeWarning.explanation}*`);
    }

    if (intel.paymentRisks.length > 0) {
      lines.push(``);
      lines.push(`### Payment Risks`);
      for (const pr of intel.paymentRisks) {
        lines.push(`- **${pr.paymentType.replace("_", " ").toUpperCase()}:** ${pr.cautionReason}`);
        lines.push(`  * Quoted: "${pr.quotedText}"`);
        lines.push(`  * Recommendation: ${pr.recommendedVerificationStep}`);
      }
    }

    if (intel.sensitiveDataRequests.length > 0) {
      lines.push(``);
      lines.push(`### Sensitive Information Requests`);
      for (const s of intel.sensitiveDataRequests) {
        lines.push(`- **${s.dataCategory.replace("_", " ").toUpperCase()}:** ${s.riskExplanation}`);
        if (s.quotedText) lines.push(`  * Quoted: "${s.quotedText}"`);
      }
    }

    if (intel.claims.length > 0) {
      lines.push(``);
      lines.push(`### Claim-by-Claim Verification Ledger`);
      for (const c of intel.claims) {
        lines.push(`- **[${c.evaluation.toUpperCase()}]** ${c.claimText}`);
        lines.push(`  * *Explanation:* ${c.explanation}`);
        if (c.sourceUrl) lines.push(`  * *Source:* [${c.sourceType || "Reference"}](${c.sourceUrl})`);
      }
    }

    if (intel.independentVerificationRoutes.length > 0) {
      lines.push(``);
      lines.push(`### Independent Verification Routes`);
      for (const iv of intel.independentVerificationRoutes) {
        lines.push(`- **${iv.title}:** ${iv.relevanceExplanation}`);
        if (iv.url) lines.push(`  * Link: ${iv.url}`);
        lines.push(`  * Established: ${iv.isIndependentlyEstablished ? "Yes (Official Registry)" : "No (Unverified Candidate)"}`);
        lines.push(`  * Limitation: ${iv.limitations}`);
      }
    }

    lines.push(``);
  }

  lines.push(`## Action Preview & Impact Simulation`);
  lines.push(`- **Proposed Action:** ${r.actionPreview.proposedAction}`);
  lines.push(`- **If You Proceed:** ${r.actionPreview.consequenceIfProceed}`);
  if (r.actionPreview.riskFactors.length > 0) {
    lines.push(`- **Key Risk Factors:**`);
    for (const rf of r.actionPreview.riskFactors) {
      lines.push(`  * ${rf}`);
    }
  }

  if (r.warningSigns.length > 0) {
    lines.push(``);
    lines.push(`## Observed Warning Signs (${r.warningSigns.length})`);
    for (const w of r.warningSigns) {
      lines.push(`- ⚠️ ${w}`);
    }
  }

  lines.push(``);
  lines.push(`---`);
  if (r.isDemo) {
    lines.push(`*DEMO NOTE: Offline demonstration mode — no live probe occurred.*`);
  }
  lines.push(`*Generated by AheadGuard AI · Your AI checks first. You act with confidence.*`);
  lines.push(`*Read-only inspection completed without logging in or submitting candidate data.*`);

  return lines.join("\n");
}

/**
 * Formats a concise, privacy-safe single-paragraph summary of the report
 * suitable for quick clipboard copying without leaking unsanitized fields.
 */
export function formatReportSummary(report: InvestigationReport): string {
  const r = createShareableReport(report);
  const org = r.claimedOrganization ? ` (${r.claimedOrganization})` : "";
  const target = r.observedDestination.finalHost || r.observedDestination.submittedHost;
  const demoPrefix = r.isDemo ? "[DEMO DATA — NOT A LIVE INVESTIGATION] " : "";
  return `${demoPrefix}AheadGuard Report: ${r.riskOutcome.toUpperCase()} for ${target}${org}. ${r.outcomeReason} Recommended Action: ${r.recommendedAction}`;
}
