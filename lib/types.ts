import { z } from "zod";

export type RiskOutcome = "Low observed risk" | "Unknown" | "Suspicious" | "High risk";
export type ThreatLikelihood = "Low" | "Moderate" | "High" | "Uncertain";
export type ConsequenceImpact = "Low" | "Moderate" | "High" | "Severe";

export interface Finding {
  label: string;
  detail: string;
  kind: "positive" | "warning" | "neutral";
  provenance: "url_structure" | "browser_observation" | "page_content" | "redirect_analysis" | "policy_rule";
}

export interface CheckPerformed {
  name: string;
  status: "completed" | "skipped" | "failed";
  detail: string;
}

export interface ModelInterpretation {
  aspect: string;
  interpretation: string;
  confidence: "low" | "medium" | "high";
}

export interface ObservedFacts {
  pageTitle?: string;
  visiblePurpose?: string;
  credentialOrPaymentRequest: boolean;
  downloadOrPermissionRequest: boolean;
  formsObserved: boolean;
  hasPasswordField: boolean;
  hasPaymentField: boolean;
  hasPunycode: boolean;
  isNumericIp: boolean;
  isHttp: boolean;
  externalLinksCount?: number;
}

export interface ActionPreview {
  proposedAction: string;
  consequenceIfProceed: string;
  riskFactors: string[];
}

export interface ObservedDestination {
  submittedUrl: string;
  normalizedUrl: string;
  submittedHost: string;
  finalUrl?: string;
  finalHost?: string;
  destinationChanged: boolean;
  redirectChain: string[];
}

export interface InvestigationReport {
  investigationId: string;
  timestamp: string;
  originalUrl: string;
  normalizedUrl: string;
  observedDestination: ObservedDestination;
  claimedOrganization?: string;
  checksPerformed: CheckPerformed[];
  evidenceItems: Finding[];
  observedFacts: ObservedFacts;
  modelInterpretations: ModelInterpretation[];
  warningSigns: string[];
  missingEvidence: string[];
  actionPreview: ActionPreview;
  riskOutcome: RiskOutcome;
  threatLikelihood: ThreatLikelihood;
  consequenceImpact: ConsequenceImpact;
  outcomeReason: string;
  recommendedAction: string;
  limitations: string[];
  replayUrl?: string;
  rawAgentOutput?: string;
  eventsCount: number;
}

export interface ProgressEvent {
  type: "started" | "streaming_url" | "progress" | "heartbeat" | "complete" | "error";
  message: string;
  timestamp: string;
  streamingUrl?: string;
  report?: InvestigationReport;
  error?: string;
}

// Zod schema for input validation
export const InputSchema = z.object({
  input: z.string().trim().min(4, "Please enter a valid URL or a message containing a URL.").max(4000),
});
