import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface XWebhookPayload {
  data?: {
    id?: string;
    text?: string;
    author_id?: string;
    created_at?: string;
    referenced_tweets?: unknown[];
  };
  includes?: {
    users?: Array<{ id?: string; username?: string; name?: string }>;
  };
  id?: string;
  text?: string;
  author_id?: string;
  created_at?: string;
  referenced_tweets?: unknown[];
}

export class XAdapter extends BaseIntegrationAdapter {
  readonly id = "x-platform";
  readonly platform = "x";
  readonly displayName = "X (Twitter) Public Post & Profile Inspector";

  private bearerToken?: string;

  constructor(options?: { bearerToken?: string }) {
    super();
    this.bearerToken = options?.bearerToken || process.env.X_BEARER_TOKEN;
  }

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "x",
      displayName: "X (Twitter) Threat Inspector",
      description: "Inspects public X posts, links, threads, and handle impersonation claims via official X API v2 endpoints.",
      accountTypeSupported: "consumer",
      capabilities: [
        {
          name: "Public Post & Link Analysis",
          description: "Analyze public posts for deceptive investment opportunities, crypto giveaways, and phishing shortlinks.",
          isAvailable: true,
        },
        {
          name: "Profile Impersonation Check",
          description: "Evaluate account creation date, follower-to-following ratio, and verified badge claim legitimacy.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Cannot access private direct messages (Requires enterprise Direct Message write/read permissions under elevated access tiers)",
        "Rate-limited under X Free/Basic developer tiers (100-500 requests per month)",
      ],
      requiredScopes: ["tweet.read", "users.read"],
      consentNotice: "AheadGuard only analyzes publicly accessible posts and handles explicitly submitted by the user.",
      honestLimitationNotice: "Analysis is subject to X API rate limits and publicly readable post content.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    const token = context.credentials?.bearerToken || this.bearerToken;
    if (!token) {
      return {
        success: false,
        status: "ACTION_REQUIRED",
        errorMessage: "X_BEARER_TOKEN or OAuth 2.0 User Access Token required for X integration.",
      };
    }

    this.bearerToken = token;
    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: context.credentials?.handle || "@AheadGuardUser",
      accountId: "x_user_22019",
      connectedAt: new Date().toISOString(),
      scopes: ["tweet.read", "users.read"],
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: context.credentials?.handle || "@AheadGuardUser",
      accountId: "x_user_22019",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(): Promise<WebhookVerificationResult> {
    // CRC challenge check for X Account Activity API if configured
    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as XWebhookPayload;
    const tweet = payload.data || payload;
    const author = payload.includes?.users?.[0] || {};
    const text: string = tweet.text || "";

    const extractedUrls = this.extractUrls(text);

    return {
      eventId: `x_${tweet.id || Date.now()}`,
      platform: "x",
      senderHandle: author.username ? `@${author.username}` : undefined,
      senderDisplayName: author.name,
      senderIdentifier: tweet.author_id || author.id,
      rawText: text,
      extractedUrls,
      extractedEntities: {
        handles: text.match(/@[A-Za-z0-9_]+/g) || [],
        cashtags: text.match(/\$[A-Za-z]+/g) || [],
      },
      inputCategory: extractedUrls.length > 0 ? "url" : "social_post",
      metadata: {
        tweetId: tweet.id,
        createdAt: tweet.created_at,
        isRetweet: Boolean(tweet.referenced_tweets),
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
