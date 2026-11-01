import { BaseIntegrationAdapter } from "./base-adapter";
import {
  IntegrationCapabilities,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";

interface EmailPayload {
  id?: string;
  subject?: string;
  body?: string;
  text?: string;
  from?: string;
  sender?: string;
  fromName?: string;
  spf?: string;
  headers?: Record<string, string>;
  attachments?: Array<{ name?: string; filename?: string }>;
}

export class EmailAdapter extends BaseIntegrationAdapter {
  readonly id = "email-guardian";
  readonly platform = "gmail";
  readonly displayName = "Email & Gmail Security Ingestion";

  async getCapabilities(): Promise<IntegrationCapabilities> {
    return {
      platform: "gmail",
      displayName: "Email Security Ingestion",
      description: "Analyzes user-submitted emails, recruitment letters, fake invoices, and header provenance (SPF, DKIM, DMARC) with least privilege.",
      accountTypeSupported: "consumer",
      capabilities: [
        {
          name: "Header Provenance Analysis",
          description: "Inspect SPF, DKIM, and DMARC alignment to detect display name spoofing and forged sender addresses.",
          isAvailable: true,
        },
        {
          name: "Recruitment & Invoice Scam Detection",
          description: "Identify fake recruitment offer letters, invoice fraud, and advance fee instructions.",
          isAvailable: true,
        },
        {
          name: "Phishing Link & Attachment Metadata Scan",
          description: "Extract and examine destination links and dangerous attachment extensions (.exe, .scr, .iso, .vbs).",
          isAvailable: true,
        },
      ],
      unsupportedCapabilities: [
        "Never requests broad mailbox read access (no https://mail.google.com/ full scope)",
        "Zero background automated scanning of unrelated personal inbox messages",
      ],
      requiredScopes: ["gmail.readonly (restricted to user-selected message only)"],
      consentNotice: "AheadGuard only evaluates specific email contents you select or forward for investigation.",
      honestLimitationNotice:
        "AheadGuard operates strictly on user-submitted messages and does not persistently sync entire email archives.",
    };
  }

  async connect(context: AuthorizationContext): Promise<ConnectionResult> {
    this.connectionStates.set(context.userId, {
      status: "CONNECTED",
      accountName: context.credentials?.email || "user@aheadguard.security",
      accountId: "email_conn_441",
      connectedAt: new Date().toISOString(),
      scopes: ["gmail.metadata_user_selected"],
    });

    return {
      success: true,
      status: "CONNECTED",
      accountName: context.credentials?.email || "user@aheadguard.security",
      accountId: "email_conn_441",
      connectedAt: new Date().toISOString(),
    };
  }

  async verifyWebhook(): Promise<WebhookVerificationResult> {
    return { isValid: true };
  }

  async normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent> {
    const payload = (rawEvent || {}) as EmailPayload;
    const subject = payload.subject || "Suspicious Email";
    const body = payload.body || payload.text || "";
    const from = payload.from || payload.sender || "";
    const spfStatus = payload.headers?.["received-spf"] || payload.spf || "neutral";
    const dkimStatus = payload.headers?.["dkim-signature"] ? "present" : "missing";

    const extractedUrls = this.extractUrls(body);
    const textCombined = `${subject}\n\n${body}`;

    return {
      eventId: `email_${payload.id || Date.now()}`,
      platform: "gmail",
      senderHandle: from,
      senderDisplayName: payload.fromName || from.split("<")[0].trim(),
      senderIdentifier: from,
      rawText: textCombined,
      extractedUrls,
      extractedEntities: {
        emails: textCombined.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [],
        attachmentNames: (payload.attachments || []).map((a) => a.name || a.filename || "attachment"),
      },
      inputCategory: "email",
      metadata: {
        subject,
        spfStatus,
        dkimStatus,
        hasAttachments: Boolean(payload.attachments?.length),
      },
      receivedAt: new Date().toISOString(),
      hasExplicitUserConsent: true,
    };
  }
}
