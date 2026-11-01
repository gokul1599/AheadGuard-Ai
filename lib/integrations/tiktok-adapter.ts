import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface TikTokPayload {
  caption?: string;
  text?: string;
  bio?: string;
  creatorHandle?: string;
  videoUrl?: string;
}

export class TikTokAdapter extends BaseIntegrationAdapter {
  readonly id = "tiktok-inspector";
  readonly platform = "tiktok";
  readonly displayName = "TikTok Promotional Video & Bio Link Inspector";

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "tiktok",
      displayName: "TikTok Link & Bio Inspector",
      description: "Screens external bio links, promotional video claims, and affiliate scam funnels submitted from TikTok.",
      accountTypeSupported: "consumer",
      capabilities: [
        {
          name: "Bio & Link-in-Bio Verification",
          description: "Inspect multi-hop redirect chains and landing pages originating from TikTok creator bios.",
          isAvailable: true,
        },
        {
          name: "Work-From-Home & Task Scam Detection",
          description: "Analyzes video description text promoting high-yield task scams and fake trading apps.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Cannot access user private messaging or algorithm feed data",
        "Operates strictly on user-submitted URLs, captions, or shared links",
      ],
      requiredScopes: ["user.info.basic (optional)"],
      consentNotice: "AheadGuard only evaluates the specific video link or bio URL you submit.",
      honestLimitationNotice: "TikTok integration is an on-demand submission workflow.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: "TikTok Submission Adapter",
      accountId: "tiktok_sub_mode",
      connectedAt: new Date().toISOString(),
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: "TikTok Submission Adapter",
      accountId: "tiktok_sub_mode",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(): Promise<WebhookVerificationResult> {
    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as TikTokPayload;
    const text: string = payload.caption || payload.text || payload.bio || "";
    const extractedUrls = this.extractUrls(text);

    return {
      eventId: `tt_${Date.now()}`,
      platform: "tiktok",
      senderHandle: payload.creatorHandle,
      rawText: text,
      extractedUrls,
      extractedEntities: {
        creator: payload.creatorHandle ? [payload.creatorHandle] : [],
      },
      inputCategory: extractedUrls.length > 0 ? "url" : "social_post",
      metadata: {
        videoUrl: payload.videoUrl,
        creatorHandle: payload.creatorHandle,
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
