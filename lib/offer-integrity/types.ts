import {
  RiskOutcome,
  ThreatLikelihood,
  ConsequenceImpact,
} from "../types";

export type OfferClaimCategory =
  | "employer_identity"
  | "vacancy_existence"
  | "role_details"
  | "recruiter_identity"
  | "recruiter_affiliation"
  | "application_destination"
  | "payment_request"
  | "payment_requirement"
  | "compensation"
  | "internship_duration"
  | "interview_process"
  | "document_request"
  | "deadline_urgency"
  | "shortlisting_claim";

export type OfferClaimStatus =
  | "OBSERVED"
  | "VERIFIED"
  | "SUPPORTED"
  | "CONTRADICTED"
  | "UNVERIFIED"
  | "CONFLICTING"
  | "NOT_CHECKED"
  | "CHECK_FAILED"
  | "INSUFFICIENT_EVIDENCE"
  | "VERIFIED_ACTIVE"
  | "VERIFIED_CLOSED"
  | "VERIFIED_EXPIRED"
  | "PARTIAL_MATCH";

export interface CanonicalOfferExtraction {
  employer: {
    name: string;
    status: "VERIFIED" | "UNVERIFIED" | "CONTRADICTED" | "NOT_CHECKED" | "CHECK_FAILED";
    rawExtracted?: string;
  };
  job: {
    title: string;
    duration?: string;
    workMode?: string;
    referenceId?: string;
    status: "VERIFIED" | "UNVERIFIED" | "CONTRADICTED" | "NOT_CHECKED" | "CHECK_FAILED";
  };
  compensation: {
    disclosedInMessage: boolean;
    amount?: number;
    amountString?: string;
    currency?: string;
    period?: "MONTHLY" | "ANNUAL" | "HOURLY" | "STIPEND" | "UNSPECIFIED";
    status: "VERIFIED" | "UNVERIFIED" | "CONTRADICTED" | "NOT_CHECKED" | "NOT_DISCLOSED_IN_LISTING";
  };
  recruiter: {
    name?: string;
    designation?: string;
    channel?: string;
    handle?: string;
    email?: string;
    phone?: string;
    affiliationStatus: "VERIFIED" | "SUPPORTED" | "UNVERIFIED" | "CONTRADICTED" | "INSUFFICIENT_EVIDENCE";
  };
  payment: {
    requested: boolean;
    amount?: number;
    amountString?: string;
    currency?: string;
    method?: string;
    upiId?: string;
    mandatory: boolean;
    refundableClaimed: boolean;
    deadline?: string;
    statedReason?: string;
  };
  selection: {
    interviewRequired: boolean;
    paymentRequiredForOfferLetter: boolean;
    shortlistedClaim: boolean;
  };
  application: {
    url?: string;
    domainClassification?: string;
  };
}

export interface OfferClaimItem {
  id: string;
  category: OfferClaimCategory;
  claimTitle: string;
  extractedValue: string;
  status: OfferClaimStatus;
  supportingEvidence?: string;
  contradictingEvidence?: string;
  sourceUrl?: string;
  sourceAuthority?: string;
  observationTime: string;
  explanation: string;
  unresolvedQuestions: string[];
  suggestedAction: string;
}

export interface VacancyVerificationDetail {
  companyName: string;
  officialDomain: string;
  officialCareersUrl?: string;
  roleTitle: string;
  isVacancyFound: boolean;
  vacancyStatus:
    | "VERIFIED_ACTIVE"
    | "VERIFIED_CLOSED"
    | "VERIFIED_EXPIRED"
    | "PARTIAL_MATCH"
    | "CONTRADICTED"
    | "UNVERIFIED"
    | "CHECK_FAILED"
    | "NOT_CHECKED"
    | "SUPPORTED"
    | "INSUFFICIENT_EVIDENCE";
  jobReferenceId?: string;
  extractedRequisitionId?: string;
  extractedTitle?: string;
  listingActive?: boolean;
  eligibility?: string;
  duration?: string;
  matchedListingUrl?: string;
  matchedListingTitle?: string;
  workArrangement?: string;
  location?: string;
  observationTime: string;
  retrievalTimestamp?: string;
  sourceUrl?: string;
  sourceAuthority: string;
  explanation: string;
  limitations: string;
  lookupStatus?: "SUCCESS" | "FAILED" | "NOT_PERFORMED";
}

export interface RecruitmentPolicyVerificationDetail {
  companyName: string;
  policyStatus:
    | "LIVE_POLICY_CONFIRMED_NO_FEE"
    | "LIVE_POLICY_EXPLICIT_GUIDANCE"
    | "CACHED_POLICY_REFERENCE"
    | "NO_POLICY_FOUND"
    | "SOURCE_UNAVAILABLE"
    | "CHECK_FAILED"
    | "CONFLICTING_POLICY_EVIDENCE"
    | "POLICY_CONFIRMED_NO_FEE"
    | "POLICY_EXPLICIT_GUIDANCE";
  hasPublishedNoFeePolicy: boolean;
  policyTitle?: string;
  policyUrl?: string;
  policyQuote?: string;
  sourceType?: "LIVE_RETRIEVAL" | "CACHED_CATALOG" | "UNAVAILABLE" | "FAILED";
  retrievalTimestamp?: string;
  cachedReferenceDate?: string;
  explanation: string;
  sourceAuthority: string;
  observationTime: string;
  limitations: string;
}

export interface SenderVerificationDetail {
  claimedRecruiterName?: string;
  claimedDesignation?: string;
  communicationChannel?: string;
  senderEmail?: string;
  senderPhone?: string;
  emailDomainMatchesCompany: boolean;
  emailDomainConsistency?:
    | "MATCHED_DOMAIN"
    | "DOMAIN_MISMATCH"
    | "GENERIC_EMAIL_PROVIDER"
    | "NOT_PROVIDED"
    | "INVALID_EMAIL";
  individualIdentityStatus?:
    | "VERIFIED_IDENTITY"
    | "PARTIALLY_CORROBORATED"
    | "UNVERIFIED"
    | "CONTRADICTED"
    | "NOT_CHECKED";
  employerAffiliationStatus?:
    | "VERIFIED_AFFILIATION"
    | "SUPPORTED_AFFILIATION"
    | "UNVERIFIED_AFFILIATION"
    | "CONTRADICTED_AFFILIATION"
    | "NOT_CHECKED";
  affiliationStatus: "VERIFIED" | "SUPPORTED" | "UNVERIFIED" | "CONTRADICTED" | "INSUFFICIENT_EVIDENCE";
  explanation: string;
  independentlyEstablished: boolean;
  recommendedVerificationChannel?: string;
  limitations: string;
}

export interface ApplicationDestinationDetail {
  submittedUrl?: string;
  normalizedUrl?: string;
  finalDomain?: string;
  destinationType:
    | "OFFICIAL_CAREERS_PORTAL"
    | "AUTHORIZED_ATS_PLATFORM"
    | "UNVERIFIED_THIRD_PARTY"
    | "SUSPICIOUS_REDIRECT"
    | "NO_DESTINATION_PROVIDED";
  isDomainConsistent: boolean;
  explanation: string;
  redirectChain: string[];
  observationTime: string;
}

export interface PaymentRequirementDetail {
  paymentRequested: boolean;
  amount?: string;
  currency?: string;
  amountDisclosed?: boolean;
  feeCategory?: string;
  paymentMethod?: string;
  upiId?: string;
  deadline?: string;
  refundabilityClaimed?: boolean;
  isMandatory?: boolean;
  statedReason?: string;
  paymentChannel?: string;
  claimedRecipient?: string;
  paymentStatus: "CONTRADICTED" | "UNVERIFIED" | "NOT_REQUESTED" | "OBSERVED";
  explanation: string;
  conflictsWithPolicy: boolean;
  cautionNotice: string;
}

export interface OfferIntegrityInput {
  offerMessage: string;
  claimedCompany?: string;
  claimedRole?: string;
  recruiterName?: string;
  recruiterDesignation?: string;
  senderEmail?: string;
  senderPhone?: string;
  vacancyUrl?: string;
  applicationUrl?: string;
  paymentAmount?: string;
  paymentReason?: string;
  allowLiveCrawl?: boolean;
  simulateCheckFailure?: boolean;
  simulatePolicyFailure?: boolean;
  simulateTinyFishFailure?: boolean;
  tinyFishApiKey?: string;
}

export interface OfferIntegrityReport {
  investigationId: string;
  timestamp: string;
  input: OfferIntegrityInput;
  riskOutcome: RiskOutcome;
  threatLikelihood: ThreatLikelihood;
  consequenceImpact: ConsequenceImpact;
  coreDistinctionNotice: string;
  overallAssessment: {
    verdictTitle: string;
    verdictSummary: string;
    strongestEvidence: string;
    mostConsequentialFinding: string;
    recommendedAction: string;
  };
  offerBreakdown: {
    vacancy: VacancyVerificationDetail;
    policy: RecruitmentPolicyVerificationDetail;
    sender: SenderVerificationDetail;
    destination: ApplicationDestinationDetail;
    payment: PaymentRequirementDetail;
  };
  claimsLedger: OfferClaimItem[];
  canonicalExtraction?: CanonicalOfferExtraction;
  recruitmentIndicators?: import("../recruitment-intelligence").RecruitmentRiskIndicatorItem[];
  trustGapMapNodes: Array<{
    id: string;
    claim: string;
    status: OfferClaimStatus;
    evidence: string;
    sourceUrl?: string;
    sourceAuthority?: string;
  }>;
  sourceExplorer: Array<{
    title: string;
    domain: string;
    url: string;
    observationTime: string;
    relevantFinding: string;
    sourceCategory: "Official Careers Portal" | "Recruitment Policy Page" | "Public Job Board" | "Unverified Message";
    authorityLevel: "Authoritative Primary" | "Official Corporate" | "Third-Party Platform" | "Untrusted Input";
    limitations: string;
  }>;
  safeActionPlan: {
    primaryWarning: string;
    keyRecommendation: string;
    verifiedApplicationRoute?: string;
    stepByStepActions: string[];
    whatNotToDo: string[];
    independentVerificationSteps: string[];
  };
  investigationLimitations: string[];
  tinyFishResearchOutcome?: {
    invoked: boolean;
    streamingUrl?: string;
    eventsCount: number;
    researchCompleted: boolean;
    sourcesDiscovered: string[];
    error?: string;
  };
}
