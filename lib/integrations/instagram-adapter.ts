import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface InstagramWebhookPayload {
  entry?: Array<{
    id?: string;
    messaging?: Array<{
      mid?: string;
      timestamp?: number;
      sender?: { id?: string };
      recipient?: { id?: string };
      message?: { mid?: string; text?: string; attachments?: unknown[] };
    }>;
  }>;
}

export class InstagramAdapter extends BaseIntegrationAdapter {
  readonly id = "instagram-professional";
  readonly platform = "instagram";
  readonly displayName = "Instagram Professional & Creator";

  private appSecret?: string;
  private verifyToken?: string;

  constructor(options?: { appSecret?: string; verifyToken?: string }) {
    super();
    this.appSecret = options?.appSecret || process.env.INSTAGRAM_APP_SECRET;
    this.verifyToken = options?.verifyToken || process.env.INSTAGRAM_VERIFY_TOKEN;
  }

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "instagram",
      displayName: "Instagram Professional",
      description: "Official Meta Graph API integration for eligible Professional and Creator accounts to verify incoming DMs, comment spam, and impersonation profiles.",
      accountTypeSupported: "professional",
      capabilities: [
        {
          name: "Direct Message Threat Screening",
          description: "Analyze incoming direct messages sent to business accounts for fake sponsorship offers, payment demands, and credential harvesting.",
          isAvailable: true,
          requiresTier: "Meta Professional Account",
        },
        {
          name: "Comment & Mention Link Verification",
          description: "Extract and investigate links posted in comments or mentions on official creator posts.",
          isAvailable: true,
        },
        {
          name: "Recruiter / Brand Sponsor Verification",
          description: "Cross-reference claimed brand partnerships against official brand registries.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Cannot access personal Instagram accounts (Meta Graph API restricts messaging APIs to Professional/Creator accounts)",
        "Cannot passively read private direct messages between third-party personal accounts without an explicit business webhook or user Share-Sheet submission",
      ],
      requiredScopes: ["instagram_manage_messages", "instagram_manage_comments", "pages_show_list"],
      consentNotice: "Only incoming messages and interactions directed to your connected professional Instagram account are processed.",
      honestLimitationNotice:
        "Meta policies strictly prohibit third-party apps from accessing personal consumer DMs. Personal users should use the 'Share to AheadGuard' action.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    const token = context.credentials?.accessToken || context.authCode;
    if (!token) {
      return {
        success: false,
        status: "ACTION_REQUIRED",
        errorMessage: "Meta OAuth access token or authCode required for Instagram connection.",
      };
    }

    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: context.credentials?.accountName || "AheadGuard Verified Creator",
      accountId: context.credentials?.accountId || "ig_prof_90210",
      connectedAt: new Date().toISOString(),
      scopes: ["instagram_manage_messages", "instagram_manage_comments"],
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: context.credentials?.accountName || "AheadGuard Verified Creator",
      accountId: context.credentials?.accountId || "ig_prof_90210",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(request: Request, rawBody?: string): Promise<WebhookVerificationResult> {
    const url = new URL(request.url);
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");

    // Subscription verification request (GET)
    if (mode === "subscribe") {
      if (token && this.verifyToken && token === this.verifyToken) {
        return { isValid: true, challengeResponse: challenge || "" };
      }
      return { isValid: false, reason: "Verify token mismatch for Instagram webhook subscription." };
    }

    // Event notification (POST)
    const signature = request.headers.get("x-hub-signature-256");
    if (!signature || !rawBody) {
      return { isValid: false, reason: "Missing X-Hub-Signature-256 header or empty payload body." };
    }

    if (this.appSecret) {
      const valid = this.verifyHmacSha256(this.appSecret, rawBody, signature, "sha256=");
      return valid ? { isValid: true } : { isValid: false, reason: "Invalid HMAC-SHA256 signature." };
    }

    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as InstagramWebhookPayload;
    const entry = payload.entry?.[0] || {};
    const messaging = entry.messaging?.[0] || {};
    const message = messaging.message || {};
    const text: string = message.text || "";
    const senderId = messaging.sender?.id || "unknown_ig_sender";

    const extractedUrls = this.extractUrls(text);

    return {
      eventId: `ig_${messaging.mid || message.mid || Date.now()}`,
      platform: "instagram",
      sourceAccountId: entry.id,
      senderIdentifier: senderId,
      rawText: text,
      extractedUrls,
      extractedEntities: {
        handles: text.match(/@[A-Za-z0-9_.]+/g) || [],
      },
      inputCategory: extractedUrls.length > 0 ? "url" : "message",
      metadata: {
        instagramBusinessId: entry.id,
        timestamp: messaging.timestamp,
        hasAttachments: Boolean(message.attachments?.length),
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
