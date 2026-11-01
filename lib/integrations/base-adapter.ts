import {
  PlatformIntegration,
  PlatformType,
  IntegrationCapabilities,
  IntegrationStatus,
  AuthorizationContext,
  ConnectionResult,
  WebhookVerificationResult,
  NormalizedPlatformEvent,
} from "./types";
import crypto from "node:crypto";

export abstract class BaseIntegrationAdapter implements PlatformIntegration {
  abstract readonly id: string;
  abstract readonly platform: PlatformType;
  abstract readonly displayName: string;

  protected connectionStates = new Map<
    string,
    {
      status: IntegrationStatus;
      accountName?: string;
      accountId?: string;
      connectedAt?: string;
      expiresAt?: string;
      scopes?: string[];
    }
  >();

  abstract getCapabilities(): Promise<IntegrationCapabilities>;

  async getConnectionStatus(userId: string): Promise<IntegrationStatus> {
    const existing = this.connectionStates.get(userId);
    return existing ? existing.status : "NOT_CONNECTED";
  }

  async getAccountDetails(userId: string) {
    return this.connectionStates.get(userId);
  }

  async disconnect(userId: string): Promise<void> {
    this.connectionStates.delete(userId);
  }

  abstract connect(context: AuthorizationContext): Promise<ConnectionResult>;
  abstract verifyWebhook(request: Request, rawBody?: string): Promise<WebhookVerificationResult>;
  abstract normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent>;

  async testConnection(userId: string): Promise<{ ok: boolean; message: string; latencyMs: number }> {
    const start = Date.now();
    const status = await this.getConnectionStatus(userId);
    const latencyMs = Date.now() - start;

    if (status === "CONNECTED" || status === "AVAILABLE") {
      return {
        ok: true,
        message: `${this.displayName} connection healthy and active.`,
        latencyMs,
      };
    }
    return {
      ok: false,
      message: `${this.displayName} is in state ${status}. Connection check failed.`,
      latencyMs,
    };
  }

  /**
   * Helper to verify HMAC-SHA256 signatures in constant time to prevent timing attacks.
   */
  protected verifyHmacSha256(secret: string, rawPayload: string, signatureHeader: string, prefix = "sha256="): boolean {
    if (!secret || !rawPayload || !signatureHeader) return false;
    try {
      const cleanSignature = signatureHeader.startsWith(prefix)
        ? signatureHeader.slice(prefix.length)
        : signatureHeader;
      const expected = crypto.createHmac("sha256", secret).update(rawPayload).digest("hex");
      const sigBuffer = Buffer.from(cleanSignature, "hex");
      const expBuffer = Buffer.from(expected, "hex");
      if (sigBuffer.length !== expBuffer.length) return false;
      return crypto.timingSafeEqual(sigBuffer, expBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Safe URL extractor helper for normalized message bodies.
   */
  protected extractUrls(text?: string): string[] {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
    const matches = text.match(urlRegex) || [];
    return Array.from(new Set(matches.map((u) => u.replace(/[.,;:!?)]+$/, ""))));
  }
}
