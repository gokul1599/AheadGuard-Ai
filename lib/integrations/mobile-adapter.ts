import { BaseIntegrationAdapter } from "./base-adapter";
import {
  PlatformType,
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

export interface MobileSharePayload {
  platform: "android" | "ios";
  sharedText?: string;
  sharedUrl?: string;
  appVersion?: string;
  deviceModel?: string;
  clientNonce?: string;
  timestamp?: number;
}

/**
 * Mobile Sharing Integration Adapter for Android Share Intents and iOS Share Sheet Extensions.
 * Accepts user-consented shares directly from the OS share menu without full app launch.
 */
export class MobileShareAdapter extends BaseIntegrationAdapter {
  readonly id = "mobile-share";
  readonly platform: PlatformType = "universal_share";
  readonly displayName = "Mobile OS Share Sheet (Android & iOS)";

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "universal_share",
      displayName: "Mobile OS Share Sheet",
      description: "Native OS Share Sheet ingestion for Android (SEND Intent) and iOS (Share Extension).",
      accountTypeSupported: "consumer",
      capabilities: [
        {
          name: "System Share Menu Ingestion",
          description: "Inspect links or text highlighted in any mobile app via the system 'Share to AheadGuard' action.",
          isAvailable: true,
        },
        {
          name: "Offer & Payment Verification",
          description: "Analyze copied job offers and payment prompts directly from mobile chat apps.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Cannot passively read screen or notifications without explicit user share action",
        "Cannot access encrypted app sandboxes without user interaction",
      ],
      requiredScopes: ["share_intent"],
      consentNotice: "AheadGuard only evaluates content you explicitly choose to share via the OS share sheet.",
      honestLimitationNotice:
        "Operates strictly on explicit user sharing. Does not run background screen scraping.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    return {
      success: true,
      status: "CONNECTED",
      accountName: "Mobile Client",
      accountId: context.userId,
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(request: Request): Promise<WebhookVerificationResult> {
    void request;
    // Client authentication handled at endpoint level
    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as MobileSharePayload;
    const text = payload.sharedText || "";
    const extractedUrls = this.extractUrls(payload.sharedUrl ? `${payload.sharedUrl} ${text}` : text);

    let category: import("./types").InputCategory = "message";
    if (text.toLowerCase().includes("interview") || text.toLowerCase().includes("internship") || text.toLowerCase().includes("job offer")) {
      category = "job_offer";
    } else if (text.toLowerCase().includes("upi") || text.toLowerCase().includes("pay") || text.toLowerCase().includes("deposit")) {
      category = "payment_screenshot";
    } else if (extractedUrls.length > 0) {
      category = "url";
    }

    return {
      eventId: `mob_${payload.clientNonce || Date.now()}`,
      platform: "universal_share",
      sourceAccountId: payload.deviceModel || "mobile_device",
      senderIdentifier: "mobile_user",
      rawText: text,
      extractedUrls,
      extractedEntities: {
        platformOS: [payload.platform || "generic_mobile"],
      },
      inputCategory: category,
      metadata: {
        appVersion: payload.appVersion,
        deviceModel: payload.deviceModel,
        timestamp: payload.timestamp,
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
