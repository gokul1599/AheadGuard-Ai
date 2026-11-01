import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface TelegramUpdatePayload {
  message?: {
    message_id?: number;
    text?: string;
    caption?: string;
    from?: { id?: number; username?: string; first_name?: string; last_name?: string; is_bot?: boolean };
    chat?: { id?: number; type?: string; title?: string };
    date?: number;
  };
  edited_message?: {
    message_id?: number;
    text?: string;
    caption?: string;
    from?: { id?: number; username?: string; first_name?: string; last_name?: string; is_bot?: boolean };
    chat?: { id?: number; type?: string; title?: string };
    date?: number;
  };
  channel_post?: {
    message_id?: number;
    text?: string;
    caption?: string;
    from?: { id?: number; username?: string; first_name?: string; last_name?: string; is_bot?: boolean };
    chat?: { id?: number; type?: string; title?: string };
    date?: number;
  };
}

export class TelegramAdapter extends BaseIntegrationAdapter {
  readonly id = "telegram-bot";
  readonly platform = "telegram";
  readonly displayName = "Telegram Safety Bot";

  private botToken?: string;
  private webhookSecret?: string;

  constructor(options?: { botToken?: string; webhookSecret?: string }) {
    super();
    this.botToken = options?.botToken || process.env.TELEGRAM_BOT_TOKEN;
    this.webhookSecret = options?.webhookSecret || process.env.TELEGRAM_WEBHOOK_SECRET;
  }

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "telegram",
      displayName: "Telegram Safety Bot",
      description: "Interactive safety bot providing on-demand scam verification via slash commands and shared messages.",
      accountTypeSupported: "bot",
      capabilities: [
        {
          name: "Interactive Slash Commands",
          description: "Inspect links, messages, companies, and QR codes via /check, /checklink, /checkcompany.",
          isAvailable: true,
        },
        {
          name: "Direct Message Analysis",
          description: "Analyze forwarded suspicious messages, suspicious bot invitations, or payment prompts.",
          isAvailable: true,
        },
        {
          name: "Group Chat Investigation",
          description: "Evaluate suspicious links posted in groups where the AheadGuard bot is an invited member.",
          isAvailable: true,
        },
        {
          name: "Scam Reporting Dossier",
          description: "Users can submit confirmed fraud evidence and generate audit-ready incident reports.",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Cannot monitor secret chats (Telegram client-side MTProto E2EE)",
        "Cannot passively read private direct messages between other users without explicit bot mention or forwarding",
      ],
      requiredScopes: ["bot_messages", "group_read_messages_when_mentioned"],
      consentNotice: "AheadGuard only analyzes messages explicitly sent to, forwarded to, or mentioning the bot.",
      honestLimitationNotice:
        "The Telegram Bot operates strictly as an interactive conversational agent. It does not monitor private user chats.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    const token = context.credentials?.botToken || this.botToken;
    if (!token) {
      return {
        success: false,
        status: "ACTION_REQUIRED",
        errorMessage: "TELEGRAM_BOT_TOKEN is required to connect the Telegram Safety Bot.",
      };
    }

    this.botToken = token;
    this.webhookSecret = context.credentials?.webhookSecret || this.webhookSecret || "aheadguard-tg-secret-v1";

    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: "@AheadGuardBot",
      accountId: "tg_bot_aheadguard",
      connectedAt: new Date().toISOString(),
      scopes: ["bot_interaction", "command_execution"],
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: "@AheadGuardBot",
      accountId: "tg_bot_aheadguard",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(request: Request): Promise<WebhookVerificationResult> {
    const secretHeader = request.headers.get("x-telegram-bot-api-secret-token");
    if (!this.webhookSecret) {
      // In development / test mode without configured secret
      return { isValid: true };
    }
    if (secretHeader && secretHeader === this.webhookSecret) {
      return { isValid: true };
    }
    return {
      isValid: false,
      reason: "Invalid or missing X-Telegram-Bot-Api-Secret-Token header.",
    };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as TelegramUpdatePayload;
    const message = payload.message || payload.edited_message || payload.channel_post || {};
    const text: string = message.text || message.caption || "";
    const sender = message.from || {};
    const chat = message.chat || {};

    const extractedUrls = this.extractUrls(text);
    const isCommand = text.startsWith("/");

    return {
      eventId: `tg_${message.message_id || Date.now()}`,
      platform: "telegram",
      sourceAccountId: String(chat.id || ""),
      senderHandle: sender.username ? `@${sender.username}` : undefined,
      senderDisplayName: [sender.first_name, sender.last_name].filter(Boolean).join(" ") || undefined,
      senderIdentifier: String(sender.id || ""),
      rawText: text,
      extractedUrls,
      extractedEntities: {
        commands: isCommand ? [text.split(" ")[0].toLowerCase()] : [],
        phoneNumbers: text.match(/\+?[1-9]\d{1,14}/g) || [],
      },
      inputCategory: extractedUrls.length > 0 ? "url" : isCommand ? "company_claim" : "message",
      metadata: {
        chatType: chat.type,
        chatTitle: chat.title,
        isBot: sender.is_bot,
        date: message.date,
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }

  /**
   * Helper to format AheadGuard investigation reports into Markdown-formatted Telegram bot replies.
   */
  formatTelegramReply(verdict: {
    riskOutcome: string;
    target: string;
    reasons: string[];
    safeAction: string;
  }): string {
    const badge =
      verdict.riskOutcome === "High risk"
        ? "🔴 *HIGH RISK*"
        : verdict.riskOutcome === "Suspicious"
        ? "🟡 *SUSPICIOUS*"
        : verdict.riskOutcome === "Low observed risk"
        ? "🟢 *LOW OBSERVED RISK*"
        : "⚪ *UNKNOWN*";

    const reasonBullets = verdict.reasons.map((r) => `• ${r}`).join("\n");

    return `${badge}\n*Target:* \`${verdict.target}\`\n\n*Observable Findings:*\n${reasonBullets}\n\n*Action Preview:*\n${verdict.safeAction}\n\n_Checked by AheadGuard AI_`;
  }
}
