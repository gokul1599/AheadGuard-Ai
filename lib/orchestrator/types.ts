import {
  InvestigationReport,
  RiskOutcome,
} from "../types";
import { PlatformType, InputCategory } from "../integrations/types";
import { TrustGraphNode, TrustGraphEdge, CrossChannelCampaignSignal } from "../trustgraph/graph-store";
import { TransactionVerificationReport } from "../transaction-truth/screenshot-forensics";
import { QrInspectionReport } from "../transaction-truth/qr-inspector";
import { OfferIntegrityReport } from "../offer-integrity/types";

export interface NormalizedInvestigationRequest {
  investigationId: string;
  userId: string;
  tenantId?: string;
  sourcePlatform: PlatformType;
  integrationId?: string;
  inputCategory: InputCategory;
  rawInput: string;
  messageText?: string;
  targetUrl?: string;
  claimedOrganization?: string;
  claimedJobRole?: string;
  recruiterContact?: string;
  ocrText?: string;
  qrPayload?: string;
  hasExplicitUserConsent: boolean;
  timestamp: string;
}

export interface StandardizedInvestigationResult {
  investigationId: string;
  timestamp: string;
  sourcePlatform: PlatformType;
  inputCategory: InputCategory;
  riskOutcome: RiskOutcome;
  threatLikelihood: "Low" | "Moderate" | "High" | "Uncertain";
  consequenceImpact: "Low" | "Moderate" | "High" | "Severe";
  outcomeReason: string;
  recommendedAction: string;
  report: InvestigationReport;
  trustGraph: {
    nodes: TrustGraphNode[];
    edges: TrustGraphEdge[];
    campaignSignal: CrossChannelCampaignSignal;
  };
  offerIntegrity?: OfferIntegrityReport;
  transactionTruth?: TransactionVerificationReport;
  qrInspection?: QrInspectionReport;
  safeActionPlan: {
    primaryWarning: string;
    stepByStepGuidance: string[];
    safeAlternative: string;
    whatNotToDo: string[];
  };
}
