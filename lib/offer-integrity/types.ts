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
  | "INSUFFICIENT_EVIDENCE";

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
  vacancyStatus: "SUPPORTED" | "CONTRADICTED" | "UNVERIFIED" | "INSUFFICIENT_EVIDENCE";
  matchedListingUrl?: string;
  matchedListingTitle?: string;
  workArrangement?: string;
  location?: string;
  observationTime: string;
  sourceAuthority: string;
  explanation: string;
  limitations: string;
}

export interface RecruitmentPolicyVerificationDetail {
  companyName: string;
  policyStatus: "POLICY_CONFIRMED_NO_FEE" | "NO_POLICY_FOUND" | "POLICY_EXPLICIT_GUIDANCE";
  hasPublishedNoFeePolicy: boolean;
  policyTitle?: string;
  policyUrl?: string;
  policyQuote?: string;
  explanation: string;
  sourceAuthority: string;
  observationTime: string;
  limitations: string;
}

export interface SenderVerificationDetail {
  claimedRecruiterName?: string;
  claimedDesignation?: string;
  senderEmail?: string;
  senderPhone?: string;
  emailDomainMatchesCompany: boolean;
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
  statedReason?: string;
  paymentChannel?: string;
  claimedRecipient?: string;
  paymentStatus: "CONTRADICTED" | "UNVERIFIED" | "NOT_REQUESTED";
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
}
