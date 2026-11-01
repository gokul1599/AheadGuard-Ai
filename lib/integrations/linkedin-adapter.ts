import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface LinkedInPayload {
  text?: string;
  message?: string;
  jobOfferText?: string;
  recruiterName?: string;
  claimedRecruiter?: string;
  companyName?: string;
  claimedOrganization?: string;
  jobRole?: string;
}

export class LinkedInAdapter extends BaseIntegrationAdapter {
  readonly id = "linkedin-recruiter";
  readonly platform = "linkedin";
  readonly displayName = "LinkedIn Recruiter & Job Offer Ingestion";

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "linkedin",
      displayName: "LinkedIn Recruiter & Job Offer Ingestion",
      description: "User-initiated intake and verification of LinkedIn InMail messages, recruiter profiles, and job offer claims.",
      accountTypeSupported: "consumer",
      capabilities: [
        {
          name: "Recruitment Fee & Deposit Warning",
          description: "Instantly flags illegal demands for laptop security deposits, visa fees, or registration costs.",
          isAvailable: true,
        },
        {
          name: "Company Domain & Careers Portal Check",
          description: "Cross-checks recruiter claims against verified company career portals and domains.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Zero unauthorized scraping of member profiles or private InMails (strictly complies with LinkedIn User Agreement)",
        "Requires explicit user submission of recruiter text, URL, or screenshot",
      ],
      requiredScopes: ["openid", "profile (user-consented submission)"],
      consentNotice: "AheadGuard only evaluates job offers and recruiter text submitted directly by you.",
      honestLimitationNotice:
        "LinkedIn does not permit third-party passive message scraping. All reviews are user-initiated.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: "LinkedIn User-Submission Mode",
      accountId: "li_user_mode",
      connectedAt: new Date().toISOString(),
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: "LinkedIn User-Submission Mode",
      accountId: "li_user_mode",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(): Promise<WebhookVerificationResult> {
    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as LinkedInPayload;
    const text: string = payload.text || payload.message || payload.jobOfferText || "";
    const recruiterName = payload.recruiterName || payload.claimedRecruiter || "Unknown Recruiter";
    const companyName = payload.companyName || payload.claimedOrganization || "";

    const extractedUrls = this.extractUrls(text);

    return {
      eventId: `li_${Date.now()}`,
      platform: "linkedin",
      senderDisplayName: recruiterName,
      senderIdentifier: recruiterName,
      rawText: text,
      extractedUrls,
      extractedEntities: {
        companies: companyName ? [companyName] : [],
        roles: payload.jobRole ? [payload.jobRole] : [],
      },
      inputCategory: "job_offer",
      metadata: {
        claimedCompany: companyName,
        recruiterName,
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
