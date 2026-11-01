import { PlatformType, InputCategory } from "@/lib/integrations/types";
import { InvestigationReport, RiskOutcome } from "@/lib/types";
import { OfferIntegrityReport } from "@/lib/offer-integrity/types";

export type JobStatus = "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED" | "DEAD_LETTER";

export interface InvestigationJobPayload {
  inputCategory: InputCategory;
  rawInput: string;
  targetUrl?: string;
  messageText?: string;
  claimedOrg?: string;
  command?: string;
  senderHandle?: string;
  senderDisplayName?: string;
  metadata?: Record<string, unknown>;
}

export type InvestigationJobResult = 
  | { type: "standard"; report: InvestigationReport; riskOutcome: RiskOutcome; safeAction: string; outcomeReason: string }
  | { type: "offer"; report: OfferIntegrityReport; riskOutcome: RiskOutcome; safeAction: string; outcomeReason: string }
  | { type: "system"; message: string };

export interface InvestigationJob {
  id: string;
  idempotencyKey: string;
  platform: PlatformType;
  senderId: string;
  sourceAccountId: string;
  status: JobStatus;
  payload: InvestigationJobPayload;
  result?: InvestigationJobResult | null;
  attempts: number;
  maxAttempts: number;
  leaseToken?: string | null;
  leaseExpiresAt?: string | null;
  errorMessage?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface EnqueueJobParams {
  idempotencyKey: string;
  platform: PlatformType;
  senderId: string;
  sourceAccountId: string;
  payload: InvestigationJobPayload;
  maxAttempts?: number;
}
