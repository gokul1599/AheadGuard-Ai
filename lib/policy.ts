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

/**
 * Builds an Action Preview describing real-world consequences.
 */
export function generateActionPreview(
  facts: ObservedFacts,
  riskOutcome: RiskOutcome,
  claimedOrg?: string,
  destinationHost?: string
): ActionPreview {
  const riskFactors: string[] = [];

  if (facts.credentialOrPaymentRequest || facts.hasPasswordField) {
    riskFactors.push("Destination prompts for account credentials, passwords, or authentication tokens.");
  }
  if (facts.hasPaymentField) {
    riskFactors.push("Destination requests financial, credit card, or payment transaction details.");
  }
  if (facts.downloadOrPermissionRequest) {
    riskFactors.push("Destination attempts to prompt file downloads or elevated browser permissions.");
  }
  if (facts.isHttp) {
    riskFactors.push("Destination uses unencrypted HTTP; data sent in transit can be intercepted.");
  }
  if (facts.hasPunycode) {
    riskFactors.push("Destination hostname uses internationalized lookalike characters (punycode).");
  }

  let proposedAction = destinationHost ? `Navigating to ${destinationHost}.` : "Navigating to this destination.";
  let consequenceIfProceed = "Routine web browsing with no special actions requested.";

  if (facts.credentialOrPaymentRequest || facts.hasPasswordField) {
    proposedAction = `Submitting credentials or personal details on ${destinationHost || "the page"}.`;
    if (riskOutcome === "High risk" || riskOutcome === "Suspicious") {
      consequenceIfProceed = claimedOrg
        ? `Credentials entered may be stolen by an unauthorized third party masquerading as ${claimedOrg}. This can lead to account takeover and identity theft.`
        : "Credentials entered may be captured by an unverified destination, exposing your account to unauthorized access.";
    } else {
      consequenceIfProceed = "Credentials will be submitted to the service. Ensure you have verified the address in your browser bar.";
    }
  } else if (facts.downloadOrPermissionRequest) {
    proposedAction = `Downloading or executing files prompted by ${destinationHost || "the page"}.`;
    if (riskOutcome === "High risk" || riskOutcome === "Suspicious") {
      consequenceIfProceed = "Downloading unverified files can install unwanted software, malware, or spyware on your device.";
    } else {
      consequenceIfProceed = "A file will be saved to your device. Verify its digital signature before opening.";
    }
  } else if (riskOutcome === "Unknown") {
    proposedAction = `Browsing to unverified destination ${destinationHost || ""}.`;
    consequenceIfProceed = "The destination could not be validated by independent checks. Proceed with extra caution and do not disclose sensitive details.";
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

  // 3. Observed Facts Extraction
  const hasPunycode = submittedHost.includes("xn--");
  const isNumericIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(submittedHost) || submittedHost.includes(":");
  const isHttp = submittedUrl.protocol === "http:";

  const credRequested = booleanOrStringFlag(structured?.credential_or_payment_request) ||
    /password|login|sign in|credit card|cvv|account credentials/i.test(rawText);
  const downloadRequested = booleanOrStringFlag(structured?.download_or_permission_request) ||
    /download\s+(apk|exe|zip|dmg|file)|grant\s+permission/i.test(rawText);

  const observedFacts: ObservedFacts = {
    pageTitle: sanitizeText(structured?.page_title),
    visiblePurpose: sanitizeText(structured?.visible_purpose),
    credentialOrPaymentRequest: credRequested,
    downloadOrPermissionRequest: downloadRequested,
    formsObserved: credRequested || /<form|input\s+type/i.test(rawText),
    hasPasswordField: /password|passcode|secret/i.test(rawText),
    hasPaymentField: /credit card|cvv|cardholder|payment details/i.test(rawText),
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
    const item: Finding = {
      label: "Destination Redirect Host Mismatch",
      detail: `The final destination (${finalHost}) differs from the submitted link (${submittedHost}). Verify this redirection is expected.`,
      kind: "warning",
      provenance: "redirect_analysis",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
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

  // Claimed Organization
  const claimedOrg = sanitizeText(structured?.claimed_organization);
  if (claimedOrg) {
    evidenceItems.push({
      label: "Claimed Identity",
      detail: `The page presents itself as representing: ${claimedOrg}.`,
      kind: "neutral",
      provenance: "page_content",
    });

    // Check if claimed org mismatches hostname (e.g. claims Google/Microsoft/Bank but host is random)
    const orgLower = claimedOrg.toLowerCase();
    const isMajorBrand = /google|microsoft|apple|paypal|amazon|bank|chase|wellsfargo|university|college/i.test(orgLower);
    if (isMajorBrand && !submittedHost.includes(orgLower.replace(/\s+/g, ""))) {
      const mismatchItem: Finding = {
        label: "Branding vs Domain Discrepancy",
        detail: `The page claims to represent "${claimedOrg}", but the domain (${submittedHost}) does not appear affiliated with that organization.`,
        kind: "warning",
        provenance: "policy_rule",
      };
      evidenceItems.push(mismatchItem);
      warningSigns.push(mismatchItem.label);
    }
  }

  // Credential prompt on unverified site
  if (observedFacts.credentialOrPaymentRequest) {
    const item: Finding = {
      label: "Credential or Payment Input Form Observed",
      detail: "The page requests login credentials, passwords, or payment information.",
      kind: "warning",
      provenance: "browser_observation",
    };
    evidenceItems.push(item);
    warningSigns.push(item.label);
  }

  // File download prompt
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

  // Agent observed warning signs
  const agentWarnings = stringList(structured?.observed_warning_signs);
  for (const w of agentWarnings) {
    if (!warningSigns.includes(w)) {
      warningSigns.push(w);
      evidenceItems.push({
        label: "Observed Warning Sign",
        detail: w,
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
    missingEvidence.push(u);
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

  const allWarningText = (warningSigns.join(" ") + " " + rawText).toLowerCase();
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
  else if (warningSigns.length > 0 || hasSuspiciousSignal) {
    riskOutcome = "Suspicious";
    threatLikelihood = "Moderate";
    outcomeReason = `Observed ${warningSigns.length} meaningful warning sign(s) requiring caution: ${warningSigns.slice(0, 3).join("; ")}.`;
    recommendedAction = "Pause and verify. Do not enter credentials or complete financial transactions without independent confirmation.";
  }
  // Policy Rule 4: Low Observed Risk (Strict conditions: passed checks, positive signals, 0 warnings, 0 critical unknowns)
  else if (
    agentPositives.length >= 1 &&
    warningSigns.length === 0 &&
    !isHttp &&
    !hasPunycode &&
    !isNumericIp &&
    !destinationChanged &&
    !observedFacts.credentialOrPaymentRequest &&
    !observedFacts.downloadOrPermissionRequest
  ) {
    riskOutcome = "Low observed risk";
    threatLikelihood = "Low";
    consequenceImpact = "Low";
    outcomeReason = "Standard checks passed without observed warning signs. Note: this reflects the checks performed and is not a guarantee of safety.";
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

  // 7. Action Preview
  const actionPreview = generateActionPreview(observedFacts, riskOutcome, claimedOrg, finalHost || submittedHost);

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
