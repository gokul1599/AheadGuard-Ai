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

// ==========================================
// SCAM, JOB & IDENTITY VERIFICATION INTELLIGENCE
// ==========================================

export type ClaimEvaluation = "Supported" | "Contradicted" | "Unverified";

export type ClaimCategory =
  | "employer_identity"
  | "job_role"
  | "compensation"
  | "recruitment_fee"
  | "urgency"
  | "sensitive_data"
  | "contact_info"
  | "guaranteed_hiring"
  | "general_claim";

export interface ClaimSourceReference {
  title: string;
  url: string;
  sourceType:
    | "official_corporate_site"
    | "official_careers_page"
    | "brand_registry"
    | "user_provided_careers_url"
    | "observed_destination"
    | "external_source";
  retrievedAt: string;
  snippet?: string;
}

export interface ClaimRecord {
  id: string;
  category: ClaimCategory;
  claimText: string;
  claimedOrganization?: string;
  evaluation: ClaimEvaluation;
  explanation: string;
  supportingSources?: ClaimSourceReference[];
  sourceUrl?: string;
  sourceType?: ClaimSourceReference["sourceType"] | "none";
  provenance: "message_text" | "browser_observation" | "brand_registry" | "external_source" | "user_input";
  retrievedAt: string;
  limitations?: string;
}

export type CompanyIdentityStatus =
  | "Official domain match"
  | "Affiliated domain observed"
  | "Third-party platform"
  | "Identity mismatch"
  | "Unverified identity";

export interface CompanyIdentityVerification {
  claimedOrganization?: string;
  destinationHost?: string;
  registrableDomain?: string;
  status: CompanyIdentityStatus;
  explanation: string;
  isRegisteredBrand: boolean;
  isOfficialCorporateDomain: boolean;
  isThirdPartyPlatform: boolean;
  platformName?: string;
  officialDomains: string[];
  officialCareersUrl?: string;
  officialContactUrl?: string;
  candidateCareersUrl?: string;
  isUserProvidedCareersUrlVerified?: boolean;
  verifiedAt: string;
  evidenceSources: ClaimSourceReference[];
}

export type JobVerificationStatus =
  | "Listing matched"
  | "Listing contradicted"
  | "Listing not found — unverified"
  | "Verification unavailable";

export interface JobVerificationResult {
  claimedRole?: string;
  claimedEmployer?: string;
  claimedLocation?: string;
  claimedCompensation?: string;
  recruiterContact?: string;
  status: JobVerificationStatus;
  explanation: string;
  matchedListingUrl?: string;
  checkedSources: ClaimSourceReference[];
  verifiedAt: string;
  limitations: string;
}

export interface RecruitmentFeeWarning {
  detected: boolean;
  feeType?: "application_fee" | "security_deposit" | "training_fee" | "equipment_fee" | "interview_fee" | "unspecified_fee";
  quotedText: string;
  explanation: string;
  riskLevel: "High" | "Moderate";
}

export interface PaymentRiskItem {
  id: string;
  paymentType: "fee_for_job" | "security_deposit" | "advance_payment" | "urgent_fee" | "p2p_transfer" | "inconsistent_method";
  quotedText: string;
  claimedRecipient?: string;
  cautionReason: string;
  destinationInvestigated: boolean;
  evidenceSummary: string;
  recommendedVerificationStep: string;
}

export interface SensitiveDataRequestItem {
  id: string;
  dataCategory: "password" | "otp_2fa" | "card_details" | "bank_account" | "government_id" | "personal_documents";
  source: "message_text_request" | "form_observed" | "input_field_observed" | "informational_mention";
  quotedText?: string;
  riskExplanation: string;
  isDestinationVerified: boolean;
}

export interface IndependentVerificationRoute {
  routeType: "official_careers_page" | "corporate_contact_page" | "official_homepage" | "support_portal" | "verified_job_board" | "user_provided_candidate";
  title: string;
  url?: string;
  isIndependentlyEstablished: boolean;
  relevanceExplanation: string;
  verifiableClaims: string[];
  limitations: string;
}

export interface ScamIntelligence {
  analysisMode: "link" | "message" | "job" | "report";
  messageExcerpt?: string;
  extractedUrls: string[];
  selectedTargetUrl?: string;
  companyIdentity: CompanyIdentityVerification;
  jobVerification?: JobVerificationResult;
  recruitmentFeeWarning?: RecruitmentFeeWarning;
  paymentRisks: PaymentRiskItem[];
  sensitiveDataRequests: SensitiveDataRequestItem[];
  claims: ClaimRecord[];
  independentVerificationRoutes: IndependentVerificationRoute[];
  privacyRedactionsApplied: string[];
  disclaimer: string;
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
  // Extended scam & trust intelligence
  scamIntelligence?: ScamIntelligence;
  extractedUrls?: string[];
  selectedTargetUrl?: string;
  analysisMode?: "link" | "message" | "job" | "report";
}

export interface ProgressEvent {
  type: "started" | "streaming_url" | "progress" | "heartbeat" | "complete" | "error";
  message: string;
  timestamp: string;
  streamingUrl?: string;
  report?: InvestigationReport;
  error?: string;
}

// Zod schemas for input validation
export const InputSchema = z.object({
  input: z.string().trim().min(4, "Please enter a valid URL or message.").max(10000),
  messageText: z.string().trim().max(10000).optional(),
  targetUrl: z.string().trim().max(2048).optional(),
  claimedOrganization: z.string().trim().max(200).optional(),
  claimedJobRole: z.string().trim().max(200).optional(),
  officialCareersUrl: z.string().trim().max(2048).optional(),
  analysisMode: z.enum(["link", "message", "job", "report"]).optional(),
});

export type InvestigationRequest = z.infer<typeof InputSchema>;
