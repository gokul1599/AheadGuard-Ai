import { InvestigationReport } from "./types";
import { redactSensitivePii } from "./message-intelligence";

/**
 * Strips sensitive tracking tokens, session IDs, and authentication parameters from URLs.
 */
export function sanitizeUrlForSharing(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const sensitiveParams = [
      "token", "auth", "session", "key", "secret", "sig", "signature",
      "password", "pwd", "otp", "code", "jwt", "id_token", "access_token",
      "refresh_token", "api_key", "apikey", "email", "user", "username", "uid"
    ];

    for (const key of Array.from(parsed.searchParams.keys())) {
      if (sensitiveParams.some((p) => key.toLowerCase().includes(p))) {
        parsed.searchParams.delete(key);
      }
    }

    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Produces a sanitized, privacy-safe version of an InvestigationReport suitable for sharing.
 */
export function createShareableReport(report: InvestigationReport): InvestigationReport {
  const sanitizedUrl = sanitizeUrlForSharing(report.originalUrl);
  const sanitizedNorm = sanitizeUrlForSharing(report.normalizedUrl);

  const sanitizedDestination = {
    ...report.observedDestination,
    submittedUrl: sanitizedUrl,
    normalizedUrl: sanitizedNorm,
    finalUrl: report.observedDestination.finalUrl ? sanitizeUrlForSharing(report.observedDestination.finalUrl) : undefined,
    redirectChain: (report.observedDestination.redirectChain || []).map(sanitizeUrlForSharing),
  };

  let scamIntel = report.scamIntelligence;
  if (scamIntel) {
    const redactedExcerpt = scamIntel.messageExcerpt
      ? redactSensitivePii(scamIntel.messageExcerpt).redactedText
      : undefined;

    scamIntel = {
      ...scamIntel,
      messageExcerpt: redactedExcerpt,
      extractedUrls: scamIntel.extractedUrls.map(sanitizeUrlForSharing),
      selectedTargetUrl: scamIntel.selectedTargetUrl ? sanitizeUrlForSharing(scamIntel.selectedTargetUrl) : undefined,
    };
  }

  const sanitizedOutcomeReason = redactSensitivePii(report.outcomeReason || "").redactedText;
  const sanitizedRecommendedAction = redactSensitivePii(report.recommendedAction || "").redactedText;
  const sanitizedWarningSigns = (report.warningSigns || []).map((w) => redactSensitivePii(w).redactedText);
  const sanitizedMissingEvidence = (report.missingEvidence || []).map((m) => redactSensitivePii(m).redactedText);

  return {
    ...report,
    originalUrl: sanitizedUrl,
    normalizedUrl: sanitizedNorm,
    observedDestination: sanitizedDestination,
    outcomeReason: sanitizedOutcomeReason,
    recommendedAction: sanitizedRecommendedAction,
    warningSigns: sanitizedWarningSigns,
    missingEvidence: sanitizedMissingEvidence,
    scamIntelligence: scamIntel,
  };
}

/**
 * Generates clean, formatted Markdown of the investigation report for copying or sharing.
 */
export function formatReportMarkdown(report: InvestigationReport): string {
  const r = createShareableReport(report);
  const lines: string[] = [];

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
        if (iv.url) lines.push(`  * Direct Official Link: ${iv.url}`);
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
  lines.push(`*Generated by AheadGuard AI · Your AI checks first. You act with confidence.*`);
  lines.push(`*Read-only inspection completed without logging in or submitting candidate data.*`);

  return lines.join("\n");
}
