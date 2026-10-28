import { InvestigationReport, ClaimRecord } from "./types";

export interface EvidenceCoverageStats {
  totalClaims: number;
  supportedCount: number;
  contradictedCount: number;
  unverifiedCount: number;
  completedChecksCount: number;
  totalChecksCount: number;
  hasFeeWarning: boolean;
  hasIdentityMismatch: boolean;
  coverageLevel: "Comprehensive" | "Partial" | "Sparse" | "Inconclusive";
  freshnessDate?: string;
  keyFindings: string[];
}

export interface TrustNode {
  id: string;
  label: string;
  sublabel?: string;
  type: "input" | "entity" | "infrastructure" | "claim" | "verdict";
  status: "supported" | "contradicted" | "unverified" | "neutral" | "warning";
  details: string;
  sourceUrl?: string;
  sourceType?: string;
  retrievedAt?: string;
  limitations?: string;
}

export interface TrustEdge {
  id: string;
  from: string;
  to: string;
  label: string;
  type: "corroborates" | "contradicts" | "unverified" | "leads_to";
}

export interface TrustGraphData {
  nodes: TrustNode[];
  edges: TrustEdge[];
  stats: EvidenceCoverageStats;
}

/**
 * Calculates evidence coverage metrics for an investigation report
 * without presenting false certainty or misleading safety percentages.
 */
export function calculateEvidenceCoverage(report: InvestigationReport): EvidenceCoverageStats {
  const claims = report.scamIntelligence?.claims || [];
  const checks = report.checksPerformed || [];

  const totalClaims = claims.length;
  const supportedCount = claims.filter((c) => c.evaluation === "Supported").length;
  const contradictedCount = claims.filter((c) => c.evaluation === "Contradicted").length;
  const unverifiedCount = claims.filter((c) => c.evaluation === "Unverified").length;

  const completedChecksCount = checks.filter((c) => c.status === "completed").length;
  const totalChecksCount = checks.length;

  const hasFeeWarning = Boolean(report.scamIntelligence?.recruitmentFeeWarning?.detected);
  const companyStatus = report.scamIntelligence?.companyIdentity?.status;
  const hasIdentityMismatch = companyStatus === "Identity mismatch";

  let coverageLevel: EvidenceCoverageStats["coverageLevel"] = "Sparse";
  if (report.riskOutcome === "Unknown") {
    coverageLevel = "Inconclusive";
  } else if (
    totalClaims >= 3 &&
    completedChecksCount >= 4 &&
    (supportedCount + contradictedCount >= 2 || (unverifiedCount <= 1 && totalClaims >= 2))
  ) {
    coverageLevel = "Comprehensive";
  } else if (totalClaims >= 1 || completedChecksCount >= 2) {
    coverageLevel = "Partial";
  }

  const keyFindings: string[] = [];
  if (hasFeeWarning) {
    keyFindings.push("Recruitment fee demand detected: High risk indicator.");
  }
  if (hasIdentityMismatch) {
    keyFindings.push("Domain does not match verified corporate identity.");
  }
  if (contradictedCount > 0) {
    keyFindings.push(`${contradictedCount} claim${contradictedCount > 1 ? "s" : ""} contradicted by evidence.`);
  }
  if (supportedCount > 0) {
    keyFindings.push(`${supportedCount} claim${supportedCount > 1 ? "s" : ""} verified against official records.`);
  }
  if (unverifiedCount > 0) {
    keyFindings.push(`${unverifiedCount} claim${unverifiedCount > 1 ? "s" : ""} could not be verified.`);
  }

  return {
    totalClaims,
    supportedCount,
    contradictedCount,
    unverifiedCount,
    completedChecksCount,
    totalChecksCount,
    hasFeeWarning,
    hasIdentityMismatch,
    coverageLevel,
    freshnessDate: report.timestamp,
    keyFindings,
  };
}

/**
 * Derives a structured relationship graph (Trust Gap Map) from an InvestigationReport.
 * Maps submitted input -> claimed entity -> observed infrastructure -> claims -> deterministic verdict.
 */
export function buildTrustGraph(report: InvestigationReport): TrustGraphData {
  const nodes: TrustNode[] = [];
  const edges: TrustEdge[] = [];
  const stats = calculateEvidenceCoverage(report);

  // 1. Submitted Input Node
  const inputHost = report.observedDestination?.submittedHost || "Submitted Input";
  const inputId = "node-input";
  nodes.push({
    id: inputId,
    label: inputHost,
    sublabel: report.scamIntelligence?.analysisMode ? `Mode: ${report.scamIntelligence.analysisMode}` : "Initial Target",
    type: "input",
    status: "neutral",
    details: `Input submitted: ${report.originalUrl}`,
    sourceUrl: report.originalUrl,
    retrievedAt: report.timestamp,
  });

  // 2. Claimed Entity Node
  const orgName = report.claimedOrganization || report.scamIntelligence?.companyIdentity?.claimedOrganization || "Claimed Entity";
  const entityId = "node-entity";
  const companyStatus = report.scamIntelligence?.companyIdentity?.status || "Unverified identity";
  const entityStatus =
    companyStatus === "Official domain match" || companyStatus === "Affiliated domain observed"
      ? "supported"
      : companyStatus === "Identity mismatch"
      ? "contradicted"
      : "unverified";

  nodes.push({
    id: entityId,
    label: orgName,
    sublabel: `Identity: ${companyStatus}`,
    type: "entity",
    status: entityStatus,
    details: report.scamIntelligence?.companyIdentity?.explanation || `Claimed organization: ${orgName}`,
    limitations: report.scamIntelligence?.companyIdentity?.isThirdPartyPlatform ? "Operates on third-party platform" : undefined,
  });

  edges.push({
    id: "edge-input-to-entity",
    from: inputId,
    to: entityId,
    label: "Claims Affiliation",
    type: entityStatus === "contradicted" ? "contradicts" : entityStatus === "supported" ? "corroborates" : "unverified",
  });

  // 3. Observed Infrastructure Node
  const finalHost = report.observedDestination?.finalHost || inputHost;
  const infraId = "node-infra";
  const isChanged = report.observedDestination?.destinationChanged;
  nodes.push({
    id: infraId,
    label: finalHost,
    sublabel: isChanged ? "Redirected Host" : "Observed Destination",
    type: "infrastructure",
    status: entityStatus === "contradicted" ? "contradicted" : "neutral",
    details: `Observed Host: ${finalHost}${isChanged ? ` (Redirected from ${inputHost})` : ""}`,
    sourceUrl: report.observedDestination?.finalUrl || report.observedDestination?.submittedUrl,
    retrievedAt: report.timestamp,
  });

  edges.push({
    id: "edge-input-to-infra",
    from: inputId,
    to: infraId,
    label: isChanged ? "Redirects To" : "Resolves To",
    type: isChanged ? "unverified" : "leads_to",
  });

  // 4. Claims Nodes
  const claims: ClaimRecord[] = report.scamIntelligence?.claims || [];
  claims.forEach((claim, idx) => {
    const claimNodeId = `node-claim-${idx + 1}`;
    const claimStatus =
      claim.evaluation === "Supported"
        ? "supported"
        : claim.evaluation === "Contradicted"
        ? "contradicted"
        : "unverified";

    nodes.push({
      id: claimNodeId,
      label: claim.claimText,
      sublabel: `[${claim.evaluation.toUpperCase()}] ${claim.category.replace(/_/g, " ")}`,
      type: "claim",
      status: claimStatus,
      details: claim.explanation,
      sourceUrl: claim.sourceUrl,
      sourceType: claim.sourceType,
      retrievedAt: claim.retrievedAt,
      limitations: claim.limitations,
    });

    edges.push({
      id: `edge-infra-to-claim-${idx + 1}`,
      from: infraId,
      to: claimNodeId,
      label: claim.evaluation,
      type: claimStatus === "supported" ? "corroborates" : claimStatus === "contradicted" ? "contradicts" : "unverified",
    });
  });

  // 5. Deterministic Verdict Node
  const verdictId = "node-verdict";
  const verdictStatus =
    report.riskOutcome === "Low observed risk"
      ? "supported"
      : report.riskOutcome === "High risk" || report.riskOutcome === "Suspicious"
      ? "contradicted"
      : "unverified";

  nodes.push({
    id: verdictId,
    label: report.riskOutcome,
    sublabel: `Threat: ${report.threatLikelihood} · Impact: ${report.consequenceImpact}`,
    type: "verdict",
    status: verdictStatus,
    details: report.outcomeReason,
  });

  // Connect claims or infra to verdict
  if (claims.length > 0) {
    claims.forEach((_, idx) => {
      edges.push({
        id: `edge-claim-${idx + 1}-to-verdict`,
        from: `node-claim-${idx + 1}`,
        to: verdictId,
        label: "Informs",
        type: "leads_to",
      });
    });
  } else {
    edges.push({
      id: "edge-infra-to-verdict",
      from: infraId,
      to: verdictId,
      label: "Informs Verdict",
      type: "leads_to",
    });
  }

  return {
    nodes,
    edges,
    stats,
  };
}
