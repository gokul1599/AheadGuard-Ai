import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface WhatsAppWebhookPayload {
  entry?: Array<{
    id?: string;
    changes?: Array<{
      value?: {
        messaging_product?: string;
        metadata?: { display_phone_number?: string; phone_number_id?: string };
        messages?: Array<{
          id?: string;
          from?: string;
          type?: string;
          timestamp?: string;
          text?: { body?: string };
          interactive?: { list_reply?: { title?: string } };
        }>;
      };
    }>;
  }>;
}

export class WhatsAppAdapter extends BaseIntegrationAdapter {
  readonly id = "whatsapp-business";
  readonly platform = "whatsapp";
  readonly displayName = "WhatsApp Business Cloud Platform";

  private appSecret?: string;
  private verifyToken?: string;

  constructor(options?: { appSecret?: string; verifyToken?: string }) {
    super();
    this.appSecret = options?.appSecret || process.env.WHATSAPP_APP_SECRET;
    this.verifyToken = options?.verifyToken || process.env.WHATSAPP_VERIFY_TOKEN;
  }

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "whatsapp",
      displayName: "WhatsApp Business Cloud",
      description: "Official Meta WhatsApp Business Cloud API for businesses to triage suspicious customer messages, payment requests, and fake delivery notifications.",
      accountTypeSupported: "business",
      capabilities: [
        {
          name: "Inbound Message Threat Analysis",
          description: "Inspect customer messages sent to official business WhatsApp numbers for phishing links and payment scams.",
          isAvailable: true,
        },
        {
          name: "Payment Request Verification",
          description: "Analyze UPI payment links and collect requests sent inside WhatsApp interactions.",
          isAvailable: true,
        },
        {
          name: "Automated Safety Advisories",
          description: "Send instant AheadGuard safety verification responses back through approved message templates.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Cannot access personal consumer WhatsApp inboxes (Personal WhatsApp uses Signal Protocol E2EE with zero cloud API access)",
        "Cannot silently monitor peer-to-peer chats",
      ],
      requiredScopes: ["whatsapp_business_messaging", "whatsapp_business_management"],
      consentNotice: "Only messages sent directly to your registered WhatsApp Business telephone number are evaluated.",
      honestLimitationNotice:
        "Personal WhatsApp messages are end-to-end encrypted. Consumers should use the 'Share to AheadGuard' mobile intent or Chrome Extension.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    const token = context.credentials?.accessToken || context.authCode;
    if (!token) {
      return {
        success: false,
        status: "ACTION_REQUIRED",
        errorMessage: "WhatsApp Business System User Token or Meta OAuth code required.",
      };
    }

    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: context.credentials?.phoneNumber || "+1 555-AHEADGUARD",
      accountId: context.credentials?.wabaId || "waba_prod_3301",
      connectedAt: new Date().toISOString(),
      scopes: ["whatsapp_business_messaging"],
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: context.credentials?.phoneNumber || "+1 555-AHEADGUARD",
      accountId: context.credentials?.wabaId || "waba_prod_3301",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(request: Request, rawBody?: string): Promise<WebhookVerificationResult> {
    const url = new URL(request.url);
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");

    if (mode === "subscribe") {
      if (token && this.verifyToken && token === this.verifyToken) {
        return { isValid: true, challengeResponse: challenge || "" };
      }
      return { isValid: false, reason: "Verify token mismatch for WhatsApp webhook." };
    }

    const signature = request.headers.get("x-hub-signature-256");
    if (!signature || !rawBody) {
      return { isValid: false, reason: "Missing X-Hub-Signature-256 header or empty payload." };
    }

    if (this.appSecret) {
      const valid = this.verifyHmacSha256(this.appSecret, rawBody, signature, "sha256=");
      return valid ? { isValid: true } : { isValid: false, reason: "Invalid HMAC-SHA256 signature for WhatsApp." };
    }

    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as WhatsAppWebhookPayload;
    const value = payload.entry?.[0]?.changes?.[0]?.value || {};
    const message = value.messages?.[0] || {};
    const text: string = message.text?.body || message.interactive?.list_reply?.title || "";
    const sender = message.from || "";

    const extractedUrls = this.extractUrls(text);
    const upiMatches = text.match(/[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}/g) || [];

    return {
      eventId: `wa_${message.id || Date.now()}`,
      platform: "whatsapp",
      sourceAccountId: value.metadata?.phone_number_id,
      senderIdentifier: sender,
      rawText: text,
      extractedUrls,
      extractedEntities: {
        upiIds: upiMatches,
        phoneNumbers: sender ? [sender] : [],
      },
      inputCategory: upiMatches.length > 0 ? "payment_screenshot" : extractedUrls.length > 0 ? "url" : "message",
      metadata: {
        displayPhoneNumber: value.metadata?.display_phone_number,
        messageType: message.type,
        timestamp: message.timestamp,
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
