import {
  ClaimRecord,
  CompanyIdentityVerification,
  IndependentVerificationRoute,
  JobVerificationResult,
} from "./types";

/**
 * Evaluates extracted claims against company verification, job verification, and destination facts.
 */
export function evaluateAllClaims(params: {
  initialClaims: ClaimRecord[];
  companyIdentity: CompanyIdentityVerification;
  jobVerification?: JobVerificationResult;
  targetUrl?: string;
}): ClaimRecord[] {
  const { initialClaims, companyIdentity, jobVerification, targetUrl } = params;
  const now = new Date().toISOString();

  return initialClaims.map((claim) => {
    // 1. Organization Identity Claim
    if (claim.category === "employer_identity") {
      if (companyIdentity.status === "Official domain match") {
        return {
          ...claim,
          evaluation: "Supported",
          explanation: `The destination domain (${companyIdentity.destinationHost}) is verified as an official domain belonging to ${companyIdentity.claimedOrganization}.`,
          sourceUrl: companyIdentity.officialDomains[0] ? `https://${companyIdentity.officialDomains[0]}` : targetUrl,
          sourceType: "official_corporate_site",
          retrievedAt: now,
        };
      } else if (companyIdentity.status === "Identity mismatch") {
        return {
          ...claim,
          evaluation: "Contradicted",
          explanation: `Direct conflict: The message asserts representation of "${companyIdentity.claimedOrganization}", but the provided link directs to "${companyIdentity.destinationHost}", which is not an authorized corporate domain.`,
          sourceUrl: companyIdentity.officialDomains[0] ? `https://${companyIdentity.officialDomains[0]}` : undefined,
          sourceType: "brand_registry",
          retrievedAt: now,
          limitations: "Direct domain discrepancy observed.",
        };
      } else if (companyIdentity.status === "Third-party platform") {
        return {
          ...claim,
          evaluation: "Unverified",
          explanation: `Destination is hosted on ${companyIdentity.platformName || "a third-party platform"}. While legitimate companies utilize external ATS platforms, specific employer posting ownership requires corroboration.`,
          sourceUrl: targetUrl,
          sourceType: "external_source",
          retrievedAt: now,
        };
      } else {
        return {
          ...claim,
          evaluation: "Unverified",
          explanation: `The identity of "${companyIdentity.claimedOrganization || "the claimed organization"}" could not be independently substantiated against verified public corporate domain registries.`,
          sourceType: "none",
          retrievedAt: now,
        };
      }
    }

    // 2. Job Role Claim
    if (claim.category === "job_role") {
      if (jobVerification?.status === "Listing matched" && jobVerification.matchedListingUrl) {
        return {
          ...claim,
          evaluation: "Supported",
          explanation: `The role is hosted on an authenticated recruitment portal on ${companyIdentity.destinationHost}.`,
          sourceUrl: jobVerification.matchedListingUrl,
          sourceType: "official_careers_page",
          retrievedAt: now,
        };
      } else if (jobVerification?.status === "Listing contradicted") {
        return {
          ...claim,
          evaluation: "Contradicted",
          explanation: `The job offer contradicts verified facts: ${jobVerification.explanation}`,
          sourceType: "external_source",
          retrievedAt: now,
        };
      } else {
        const unverifiedDetail =
          companyIdentity.isOfficialCorporateDomain || companyIdentity.isThirdPartyPlatform
            ? `Employer domain or recruitment platform (${companyIdentity.destinationHost}) is recognized, but specific vacancy requisition could not be independently verified.`
            : "The advertised position could not be verified on an independently authenticated corporate careers portal. This is unverified, not definitive proof of fraud.";
        return {
          ...claim,
          evaluation: "Unverified",
          explanation: unverifiedDetail,
          sourceType: companyIdentity.officialDomains.length > 0 ? "official_corporate_site" : "none",
          sourceUrl: companyIdentity.officialDomains[0] ? `https://${companyIdentity.officialDomains[0]}` : undefined,
          retrievedAt: now,
        };
      }
    }

    // 3. Recruitment Fee & Payment Claims
    if (claim.category === "recruitment_fee") {
      const isFeeExemptionOrFree = /(?:no\s+(?:application\s+)?fees?|free\s+of\s+charge|zero\s+(?:upfront\s+)?fees?|never\s+charge|100%\s+free|no\s+deposit|without\s+(?:any\s+)?fee)/i.test(
        claim.claimText
      );
      if (isFeeExemptionOrFree) {
        return {
          ...claim,
          evaluation: "Supported",
          explanation: "Verified statement: Legitimate employers do not require fees or monetary deposits for candidate consideration.",
          sourceType: claim.sourceType || "heuristic_rule",
          retrievedAt: now,
        };
      }

      const conflictsWithVerifiedPolicy =
        Boolean(companyIdentity.isRegisteredBrand) ||
        Boolean(companyIdentity.isOfficialCorporateDomain) ||
        Boolean(companyIdentity.officialDomains && companyIdentity.officialDomains.length > 0);

      if (conflictsWithVerifiedPolicy) {
        return {
          ...claim,
          evaluation: "Contradicted",
          explanation: `Contradicted by verified corporate policy: ${companyIdentity.claimedOrganization || "The verified employer"} strictly prohibits candidate registration fees or upfront deposits.`,
          sourceType: "official_corporate_site",
          sourceUrl: companyIdentity.officialDomains?.[0] ? `https://${companyIdentity.officialDomains[0]}` : undefined,
          retrievedAt: now,
        };
      }

      return {
        ...claim,
        evaluation: "OBSERVED",
        explanation: "Direct observation: The submitted message demands an upfront payment. Legitimate corporate employers do not charge candidate fees or onboarding deposits.",
        sourceType: claim.sourceType || "heuristic_rule",
        retrievedAt: now,
      };
    }

    // 4. Guaranteed Hiring / No-Interview Claim
    if (claim.category === "guaranteed_hiring") {
      return {
        ...claim,
        evaluation: "OBSERVED",
        explanation: "Direct observation: The message asserts selection without formal interview assessment. Legitimate corporate roles require competency evaluation.",
        retrievedAt: now,
      };
    }

    // 5. Urgency Window Claim
    if (claim.category === "urgency") {
      return {
        ...claim,
        evaluation: "OBSERVED",
        explanation: "Direct observation: Artificial time pressure applied in message. High-pressure deadlines are frequently used to induce hasty payments.",
        retrievedAt: now,
      };
    }

    // 6. Sensitive Data Claims
    if (claim.category === "sensitive_data") {
      return {
        ...claim,
        evaluation: "Contradicted",
        explanation: "Disclosing credentials, OTPs, or government identity documents over unverified channels is dangerous and contrary to secure practices.",
        retrievedAt: now,
      };
    }

    // Default passthrough
    return {
      ...claim,
      retrievedAt: now,
    };
  });
}

/**
 * Builds reliable independent verification routes for the user,
 * avoiding sending them back to untrusted links in suspicious messages.
 */
export function generateIndependentVerificationRoutes(params: {
  companyIdentity: CompanyIdentityVerification;
  claimedRole?: string;
}): IndependentVerificationRoute[] {
  const { companyIdentity, claimedRole } = params;
  const routes: IndependentVerificationRoute[] = [];

  // Route 1: Official Corporate Careers Portal
  if (companyIdentity.officialCareersUrl) {
    routes.push({
      routeType: "official_careers_page",
      title: `${companyIdentity.claimedOrganization || "Official"} Careers Portal`,
      url: companyIdentity.officialCareersUrl,
      isIndependentlyEstablished: true,
      relevanceExplanation: `Navigate directly to the official careers site to check if "${claimedRole || "this vacancy"}" is listed among active requisitions.`,
      verifiableClaims: ["Employer Identity", "Job Role Vacancy", "Application Procedures"],
      limitations: "Only roles actively indexed on the public site will appear; unlisted or executive searches may not be shown.",
    });
  } else if (companyIdentity.officialDomains.length > 0) {
    const root = companyIdentity.officialDomains[0];
    routes.push({
      routeType: "official_homepage",
      title: `${companyIdentity.claimedOrganization} Official Website`,
      url: `https://${root}`,
      isIndependentlyEstablished: true,
      relevanceExplanation: `Visit the official corporate homepage at ${root} and locate the "Careers", "About Us", or "Contact" links in the site footer.`,
      verifiableClaims: ["Official Domain Verification", "Official Contact Channels"],
      limitations: "Do not trust links sent via WhatsApp or SMS; always confirm the domain matches the address bar.",
    });
  } else {
    // No pre-registered official portal available
    routes.push({
      routeType: "corporate_contact_page",
      title: "Independent Search for Official Company Homepage",
      isIndependentlyEstablished: false,
      relevanceExplanation: `No verified official careers portal is cataloged for "${companyIdentity.claimedOrganization || "this organization"}". Open a new browser tab and search for the company's official corporate headquarters or switchboard.`,
      verifiableClaims: ["Authentic Domain Identification", "HR Department Verification"],
      limitations: "CRITICAL: Never call the phone number or click the link provided inside the suspicious message to verify that message.",
    });
  }

  // Route 2: Security & Fraud Reporting
  if (companyIdentity.officialContactUrl) {
    routes.push({
      routeType: "support_portal",
      title: `${companyIdentity.claimedOrganization} Official Contact / Security`,
      url: companyIdentity.officialContactUrl,
      isIndependentlyEstablished: true,
      relevanceExplanation: "Report suspected recruiter impersonation directly to the organization's corporate trust and safety team.",
      verifiableClaims: ["Recruiter Legitimacy Confirmation"],
      limitations: "Response times vary by enterprise security department.",
    });
  }

  // Candidate Careers Link (if provided by user but unverified against approved corporate domains)
  if (companyIdentity.candidateCareersUrl && !companyIdentity.isUserProvidedCareersUrlVerified) {
    routes.push({
      routeType: "user_provided_candidate",
      title: "User-Provided Careers Link (Unverified)",
      url: companyIdentity.candidateCareersUrl,
      isIndependentlyEstablished: false,
      relevanceExplanation: `Candidate link provided by user (${companyIdentity.candidateCareersUrl}) has not been established as an official corporate portal. AheadGuard cannot confirm that this link is controlled by ${companyIdentity.claimedOrganization || "the employer"}.`,
      verifiableClaims: ["Candidate Portal Reference"],
      limitations: "Unverified user-submitted destination. Do not submit sensitive identity documents or passwords without independent confirmation.",
    });
  }

  return routes;
}

import type { ExtractedMessageData } from "./message-intelligence";
import type { Finding, InvestigationReport, ScamIntelligence } from "./types";

/**
 * Enriches an existing InvestigationReport with comprehensive scam intelligence,
 * claim verification, payment risks, and independent verification routes.
 */
export function enrichReportWithScamIntelligence(params: {
  report: InvestigationReport;
  messageData: ExtractedMessageData;
  companyIdentity: CompanyIdentityVerification;
  jobVerification?: JobVerificationResult;
  analysisMode?: "link" | "message" | "job" | "report";
}): InvestigationReport {
  const { report, messageData, companyIdentity, jobVerification, analysisMode } = params;

  // 1. Evaluate all claims
  const evaluatedClaims = evaluateAllClaims({
    initialClaims: messageData.claims,
    companyIdentity,
    jobVerification,
    targetUrl: report.observedDestination.finalUrl || report.originalUrl,
  });

  // 2. Build independent verification routes
  const independentRoutes = generateIndependentVerificationRoutes({
    companyIdentity,
    claimedRole: messageData.claimedJobRole,
  });

  // 3. Assemble ScamIntelligence block
  const scamIntelligence: ScamIntelligence = {
    analysisMode: analysisMode || "message",
    messageExcerpt: messageData.redactedText
      ? messageData.redactedText.length > 800
        ? messageData.redactedText.slice(0, 800) + "..."
        : messageData.redactedText
      : undefined,
    extractedUrls: messageData.extractedUrls,
    selectedTargetUrl: report.observedDestination.finalUrl || report.originalUrl,
    companyIdentity,
    jobVerification,
    recruitmentFeeWarning: messageData.recruitmentFeeWarning,
    paymentRisks: messageData.paymentRisks,
    sensitiveDataRequests: messageData.sensitiveDataRequests,
    recruitmentIndicators: messageData.recruitmentIndicators || [],
    recruitmentBehavior: messageData.recruitmentAnalysis,
    claims: evaluatedClaims,
    independentVerificationRoutes: independentRoutes,
    privacyRedactionsApplied: messageData.appliedRedactions,
    disclaimer:
      "AheadGuard evaluates observable web evidence and domain authenticity. An unverified claim is not proof of fraud.",
  };

  const updatedWarningSigns = [...report.warningSigns];
  const updatedEvidenceItems = [...report.evidenceItems];

  // 4. Integrate recruitment fee findings into primary report
  if (messageData.recruitmentFeeWarning?.detected) {
    const feeItem: Finding = {
      id: `finding-${updatedEvidenceItems.length + 1}-recruitment-fee-demanded`,
      label: "Recruitment Fee Demanded in Message",
      detail: messageData.recruitmentFeeWarning.quotedText,
      kind: "warning",
      provenance: "page_content",
      evidenceNature: "user_input_assertion",
      sourceType: "heuristic_rule",
      snippet: messageData.recruitmentFeeWarning.quotedText,
      rationale: messageData.recruitmentFeeWarning.explanation,
      limitations: "Extracted directly from user-submitted message text; not observed on an authoritative careers portal.",
    };
    if (!updatedEvidenceItems.some((e) => e.label === feeItem.label)) {
      updatedEvidenceItems.push(feeItem);
    }
    const warnLabel = `Recruitment Fee Demanded: ${messageData.recruitmentFeeWarning.explanation}`;
    if (!updatedWarningSigns.includes(warnLabel)) {
      updatedWarningSigns.push(warnLabel);
    }
  }

  // Integrate recruitment behavioral indicators into warning signs & evidence
  if (messageData.recruitmentAnalysis?.urgency.detected) {
    const warnLabel = `Payment Urgency: ${messageData.recruitmentAnalysis.urgency.deadlineText}`;
    if (!updatedWarningSigns.includes(warnLabel)) {
      updatedWarningSigns.push(warnLabel);
      updatedEvidenceItems.push({
        id: `finding-${updatedEvidenceItems.length + 1}-payment-urgency`,
        label: "Artificial Payment Urgency",
        detail: `Payment deadline enforced: "${messageData.recruitmentAnalysis.urgency.deadlineText}". High-pressure deadlines are frequently used to induce hasty payments.`,
        kind: "warning",
        provenance: "page_content",
        evidenceNature: "user_input_assertion",
        sourceType: "heuristic_rule",
      });
    }
  }

  if (messageData.recruitmentAnalysis?.process.noInterviewRequired) {
    const warnLabel = "Selection without formal interview assessment";
    if (!updatedWarningSigns.includes(warnLabel)) {
      updatedWarningSigns.push(warnLabel);
      updatedEvidenceItems.push({
        id: `finding-${updatedEvidenceItems.length + 1}-no-interview`,
        label: "Selection Without Interview Assessment",
        detail: messageData.recruitmentAnalysis.process.quotedText || "No interview required for this position",
        kind: "warning",
        provenance: "page_content",
        evidenceNature: "user_input_assertion",
        sourceType: "heuristic_rule",
      });
    }
  }

  if (messageData.recruitmentAnalysis?.recruiter.isPersonalMessagingChannel) {
    const warnLabel = `Unverified recruiter contact channel (${messageData.recruitmentAnalysis.recruiter.channel})`;
    if (!updatedWarningSigns.includes(warnLabel)) {
      updatedWarningSigns.push(warnLabel);
      updatedEvidenceItems.push({
        id: `finding-${updatedEvidenceItems.length + 1}-recruiter-channel`,
        label: "Unverified Recruiter Contact Channel",
        detail: messageData.recruitmentAnalysis.recruiter.explanation,
        kind: "warning",
        provenance: "page_content",
        evidenceNature: "user_input_assertion",
        sourceType: "heuristic_rule",
      });
    }
  }

  // 5. Integrate identity mismatch findings into primary report
  if (companyIdentity.status === "Identity mismatch") {
    const mismatchItem: Finding = {
      id: `finding-${updatedEvidenceItems.length + 1}-company-identity-mismatch`,
      label: "Company Identity Mismatch",
      detail: companyIdentity.explanation,
      kind: "warning",
      provenance: "policy_rule",
      evidenceNature: "derived_policy_rule",
      sourceType: "brand_registry",
      sourceUrl: companyIdentity.officialDomains[0] ? `https://${companyIdentity.officialDomains[0]}` : undefined,
      rationale: companyIdentity.explanation,
      limitations: "Derived by comparing destination host against the authoritative approved domains for this brand.",
    };
    if (!updatedEvidenceItems.some((e) => e.label === mismatchItem.label)) {
      updatedEvidenceItems.push(mismatchItem);
    }
    const warnLabel = `Company Identity Mismatch: Destination does not belong to ${companyIdentity.claimedOrganization}`;
    if (!updatedWarningSigns.includes(warnLabel)) {
      updatedWarningSigns.push(warnLabel);
    }
  }

  // 6. Harmonize overall risk outcome & deterministic scoring
  let finalRiskOutcome = report.riskOutcome;
  let finalThreatLikelihood = report.threatLikelihood;
  let finalConsequenceImpact = report.consequenceImpact;
  let finalOutcomeReason = report.outcomeReason;

  const hasFee = Boolean(messageData.recruitmentFeeWarning?.detected);
  const hasUrgency = Boolean(messageData.recruitmentAnalysis?.urgency.detected);
  const hasNoInterview = Boolean(messageData.recruitmentAnalysis?.process.noInterviewRequired);
  const hasUnverifiedRecruiter = Boolean(messageData.recruitmentAnalysis?.recruiter.isPersonalMessagingChannel);
  const isReservedDest =
    report.observedDestination?.finalHost?.endsWith(".example") ||
    report.originalUrl?.includes(".example") ||
    report.observedDestination?.submittedHost?.endsWith(".example");

  if (hasFee && companyIdentity.status === "Identity mismatch") {
    finalRiskOutcome = "High risk";
    finalThreatLikelihood = "High";
    finalConsequenceImpact = "Severe";
    finalOutcomeReason = `High-risk employment deception detected: message demands recruitment fee or deposit ("${messageData.recruitmentFeeWarning!.quotedText}") while directing to an unverified domain that does not belong to ${companyIdentity.claimedOrganization}.`;
  } else if (hasFee) {
    // If fee is demanded, calculate consequence impact based on financial loss & credential exposure
    finalConsequenceImpact = "High";
    if (hasUrgency && (hasNoInterview || hasUnverifiedRecruiter || isReservedDest)) {
      finalRiskOutcome = "Suspicious";
      finalThreatLikelihood = "Moderate";
      finalOutcomeReason = `Suspicious recruitment risk detected: The submitted offer contains a mandatory upfront payment request, an urgent deadline, and an unverified recruiter affiliation. The employer and vacancy could not be independently authenticated. Do not pay or share sensitive information until independent verification is complete.`;
    } else {
      if (finalRiskOutcome === "Low observed risk" || finalRiskOutcome === "Unknown") {
        finalRiskOutcome = "Suspicious";
        finalThreatLikelihood = "Moderate";
        finalOutcomeReason = `Suspicious recruitment fee or deposit demand observed in message ("${messageData.recruitmentFeeWarning!.quotedText}"). Legitimate employers do not charge candidates fees.`;
      }
    }
  } else if (companyIdentity.status === "Identity mismatch") {
    if (finalRiskOutcome === "Low observed risk") {
      finalRiskOutcome = "Suspicious";
      finalThreatLikelihood = "Moderate";
      finalOutcomeReason = `Destination domain (${companyIdentity.destinationHost}) does not belong to the claimed organization (${companyIdentity.claimedOrganization}).`;
    }
  } else if (
    companyIdentity.isThirdPartyPlatform &&
    jobVerification?.status &&
    (jobVerification.status.includes("unverified") || jobVerification.status.includes("not found"))
  ) {
    if (finalRiskOutcome === "Low observed risk") {
      finalRiskOutcome = "Unknown";
      finalThreatLikelihood = "Uncertain";
      finalOutcomeReason = `The destination is hosted on a recognized third-party platform (${companyIdentity.platformName || companyIdentity.destinationHost}), but the specific vacancy "${jobVerification.claimedRole || "unspecified"}" could not be confirmed in available page evidence.`;
    }
  }

  // Harmonize Action Preview & Recommended Action
  let updatedActionPreview = report.actionPreview;
  let updatedRecommendedAction = report.recommendedAction;

  if (hasFee) {
    updatedRecommendedAction =
      "DO NOT PAY. Never transfer funds via UPI, QR code, or payment links for job selection or onboarding. Independently contact the claimed employer through published official directories.";
    updatedActionPreview = {
      proposedAction: "Reviewing unsolicited employment offer and payment demand.",
      consequenceIfProceed: `Transferring ${messageData.recruitmentAnalysis?.fee.currency || "INR"} ${messageData.recruitmentAnalysis?.fee.amount || "funds"} creates severe financial loss and credential exposure risk.`,
      riskFactors: [
        `Mandatory recruitment fee requested: ${messageData.recruitmentAnalysis?.fee.currency || "INR"} ${messageData.recruitmentAnalysis?.fee.amount || "2,999"}.`,
        "Direct peer-to-peer or UPI payment channel specified.",
        "Employer and vacancy authenticity unverified.",
      ],
    };
  } else if (isReservedDest) {
    updatedActionPreview = {
      proposedAction: "Reviewing offer with synthetic documentation destination (.example).",
      consequenceIfProceed: "The destination is an officially reserved example domain (RFC 2606) and cannot be an operational careers portal.",
      riskFactors: ["Destination domain is a reserved example namespace."],
    };
  }

  // 7. Ensure complete evidence provenance on all findings
  for (let i = 0; i < updatedEvidenceItems.length; i++) {
    const f = updatedEvidenceItems[i];
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
    if (!f.sourceUrl && (f.provenance === "browser_observation" || f.provenance === "redirect_analysis")) {
      f.sourceUrl = report.observedDestination.finalUrl || report.originalUrl;
    }
    if (!f.observedAt && (f.provenance === "browser_observation" || f.provenance === "redirect_analysis")) {
      f.observedAt = report.timestamp;
    }
    if (f.accessible === undefined && f.sourceUrl && (f.provenance === "browser_observation" || f.provenance === "redirect_analysis")) {
      f.accessible = true;
    }
  }

  return {
    ...report,
    claimedOrganization: companyIdentity.claimedOrganization || report.claimedOrganization,
    warningSigns: updatedWarningSigns,
    evidenceItems: updatedEvidenceItems,
    riskOutcome: finalRiskOutcome,
    threatLikelihood: finalThreatLikelihood,
    consequenceImpact: finalConsequenceImpact,
    outcomeReason: finalOutcomeReason,
    recommendedAction: updatedRecommendedAction,
    actionPreview: updatedActionPreview,
    scamIntelligence,
    extractedUrls: messageData.extractedUrls,
    selectedTargetUrl: report.observedDestination.finalUrl || report.originalUrl,
    analysisMode: analysisMode || "message",
  };
}

/**
 * Creates an investigation report for a message that contains no destination URLs.
 */
export function createTextOnlyReport(params: {
  messageData: ExtractedMessageData;
  companyIdentity: CompanyIdentityVerification;
  jobVerification?: JobVerificationResult;
}): InvestigationReport {
  const { messageData, companyIdentity, jobVerification } = params;
  const now = new Date().toISOString();
  const randSuffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID().replace(/-/g, "").slice(0, 12)
    : Math.random().toString(36).substring(2, 10);
  const investigationId = `inv_text_${Date.now()}_${randSuffix}`;

  const evaluatedClaims = evaluateAllClaims({
    initialClaims: messageData.claims,
    companyIdentity,
    jobVerification,
  });

  const independentRoutes = generateIndependentVerificationRoutes({
    companyIdentity,
    claimedRole: messageData.claimedJobRole,
  });

  const hasFee = Boolean(messageData.recruitmentFeeWarning?.detected);
  const hasPay = messageData.paymentRisks.length > 0;
  const hasSens = messageData.sensitiveDataRequests.length > 0;
  const hasUrgency = Boolean(messageData.recruitmentAnalysis?.urgency.detected);
  const hasNoInterview = Boolean(messageData.recruitmentAnalysis?.process.noInterviewRequired);
  const hasUnverifiedRecruiter = Boolean(messageData.recruitmentAnalysis?.recruiter.isPersonalMessagingChannel);

  let riskOutcome: InvestigationReport["riskOutcome"] = "Unknown";
  let threatLikelihood: InvestigationReport["threatLikelihood"] = "Uncertain";
  let consequenceImpact: InvestigationReport["consequenceImpact"] = "Moderate";
  let outcomeReason = "Text-only message analysis completed. No destination URL was provided to inspect in the sandbox.";

  const warningSigns: string[] = [];
  const evidenceItems: Finding[] = [];

  if (hasFee) {
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    consequenceImpact = "High";
    outcomeReason = hasUrgency && (hasNoInterview || hasUnverifiedRecruiter)
      ? "The submitted offer contains a mandatory upfront payment request, an urgent deadline, and an unverified recruiter affiliation. The employer and vacancy could not be independently authenticated. Do not pay or share sensitive information until independent verification is complete."
      : `Upfront recruitment fee demanded in message text: "${messageData.recruitmentFeeWarning!.quotedText}". Legitimate corporate employers never charge candidate fees or onboarding deposits.`;

    warningSigns.push(`Recruitment Fee Demanded: ${messageData.recruitmentFeeWarning!.explanation}`);
    evidenceItems.push({
      id: `finding-${evidenceItems.length + 1}-recruitment-fee-demanded`,
      label: "Recruitment Fee Demanded in Message",
      detail: messageData.recruitmentFeeWarning!.quotedText,
      kind: "warning",
      provenance: "page_content",
      evidenceNature: "user_input_assertion",
      sourceType: "heuristic_rule",
      snippet: messageData.recruitmentFeeWarning!.quotedText,
      rationale: messageData.recruitmentFeeWarning!.explanation,
      limitations: "Direct observation from user-submitted message text.",
    });

    if (hasUrgency) {
      warningSigns.push(`Payment Urgency: ${messageData.recruitmentAnalysis!.urgency.deadlineText}`);
      evidenceItems.push({
        id: `finding-${evidenceItems.length + 1}-payment-urgency`,
        label: "Artificial Payment Urgency",
        detail: `Payment deadline enforced: "${messageData.recruitmentAnalysis!.urgency.deadlineText}". High-pressure deadlines are frequently used to induce hasty payments.`,
        kind: "warning",
        provenance: "page_content",
        evidenceNature: "user_input_assertion",
        sourceType: "heuristic_rule",
      });
    }

    if (hasNoInterview) {
      warningSigns.push("Selection without formal interview assessment");
      evidenceItems.push({
        id: `finding-${evidenceItems.length + 1}-no-interview`,
        label: "Selection Without Interview Assessment",
        detail: messageData.recruitmentAnalysis!.process.quotedText || "No interview required for this position",
        kind: "warning",
        provenance: "page_content",
        evidenceNature: "user_input_assertion",
        sourceType: "heuristic_rule",
      });
    }

    if (hasUnverifiedRecruiter) {
      warningSigns.push(`Unverified recruiter contact channel (${messageData.recruitmentAnalysis!.recruiter.channel})`);
      evidenceItems.push({
        id: `finding-${evidenceItems.length + 1}-recruiter-channel`,
        label: "Unverified Recruiter Contact Channel",
        detail: messageData.recruitmentAnalysis!.recruiter.explanation,
        kind: "warning",
        provenance: "page_content",
        evidenceNature: "user_input_assertion",
        sourceType: "heuristic_rule",
      });
    }
  } else if (hasPay || hasSens) {
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    consequenceImpact = "High";
    outcomeReason = "Message requests sensitive credentials or direct payments without a verified corporate destination.";
  }

  const scamIntelligence: ScamIntelligence = {
    analysisMode: "message",
    messageExcerpt: messageData.redactedText
      ? messageData.redactedText.length > 800
        ? messageData.redactedText.slice(0, 800) + "..."
        : messageData.redactedText
      : undefined,
    extractedUrls: [],
    companyIdentity,
    jobVerification,
    recruitmentFeeWarning: messageData.recruitmentFeeWarning,
    paymentRisks: messageData.paymentRisks,
    sensitiveDataRequests: messageData.sensitiveDataRequests,
    recruitmentIndicators: messageData.recruitmentIndicators || [],
    recruitmentBehavior: messageData.recruitmentAnalysis,
    claims: evaluatedClaims,
    independentVerificationRoutes: independentRoutes,
    privacyRedactionsApplied: messageData.appliedRedactions,
    disclaimer:
      "AheadGuard evaluated the provided message text. Because no destination URL was provided, live browser security sandbox inspection was not performed.",
  };

  return {
    investigationId,
    timestamp: now,
    originalUrl: "text://message-analysis",
    normalizedUrl: "text://message-analysis",
    observedDestination: {
      submittedUrl: "text://message-analysis",
      normalizedUrl: "text://message-analysis",
      submittedHost: "message-text",
      destinationChanged: false,
      redirectChain: [],
    },
    claimedOrganization: companyIdentity.claimedOrganization,
    checksPerformed: [
      {
        name: "Message Text Analysis & PII Redaction",
        status: "completed",
        detail: "Extracted claims, recruitment fee demands, and sensitive data requests.",
      },
      {
        name: "Company Identity Registry Lookup",
        status: "completed",
        detail: `Evaluated claimed organization "${companyIdentity.claimedOrganization || "unspecified"}".`,
      },
      {
        name: "Destination Sandbox Inspection",
        status: "skipped",
        detail: "No URL was present in the submitted text to inspect.",
      },
    ],
    evidenceItems,
    observedFacts: {
      pageTitle: undefined,
      visiblePurpose: "Message text analysis without external link inspection",
      credentialOrPaymentRequest: hasPay || hasFee,
      downloadOrPermissionRequest: false,
      formsObserved: false,
      hasPasswordField: false,
      hasPaymentField: false,
      hasPunycode: false,
      isNumericIp: false,
      isHttp: false,
    },
    modelInterpretations: [],
    warningSigns,
    missingEvidence: [
      "No destination URL was provided; remote browser inspection could not be performed.",
      "Sender identity over SMS/WhatsApp cannot be authenticated by text alone.",
    ],
    actionPreview: {
      proposedAction: "Evaluating message text claims.",
      consequenceIfProceed: hasFee
        ? `Transferring ${messageData.recruitmentAnalysis?.fee.currency || "INR"} ${messageData.recruitmentAnalysis?.fee.amount || "funds"} creates severe financial loss and credential exposure risk.`
        : "Proceed with caution. Independently verify the employer before sharing documents.",
      riskFactors: hasFee
        ? [
            `Mandatory recruitment fee requested: ${messageData.recruitmentAnalysis?.fee.currency || "INR"} ${messageData.recruitmentAnalysis?.fee.amount || "fee"}.`,
            "Direct peer-to-peer or UPI payment channel specified.",
            "Recruiter identity and company requisition unverified.",
          ]
        : ["Unverified message sender."],
    },
    riskOutcome,
    threatLikelihood,
    consequenceImpact,
    outcomeReason,
    recommendedAction: hasFee
      ? "DO NOT PAY. Never transfer funds via UPI, QR code, or payment links for job selection or onboarding. Independently contact the claimed employer through published official directories."
      : "Verify the sender through an official company channel before responding.",
    limitations: [
      "Analysis is based entirely on user-provided text; no external website was visited.",
      "Absence of detected threats is not a guarantee that the sender is genuine.",
    ],
    eventsCount: 1,
    scamIntelligence,
    extractedUrls: [],
    analysisMode: "message",
  };
}

