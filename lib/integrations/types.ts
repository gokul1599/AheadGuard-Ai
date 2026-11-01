export type PlatformType =
  | "telegram"
  | "instagram"
  | "whatsapp"
  | "discord"
  | "x"
  | "gmail"
  | "linkedin"
  | "tiktok"
  | "browser_extension"
  | "universal_share";

export type IntegrationStatus =
  | "AVAILABLE"
  | "NOT_CONNECTED"
  | "CONNECTING"
  | "CONNECTED"
  | "ACTION_REQUIRED"
  | "PERMISSION_LIMITED"
  | "REVIEW_REQUIRED"
  | "TEMPORARILY_UNAVAILABLE"
  | "DISCONNECTED";

export interface IntegrationCapability {
  name: string;
  description: string;
  isAvailable: boolean;
  requiresApproval?: boolean;
  requiresTier?: string;
  limitationReason?: string;
}

export interface IntegrationCapabilities {
  platform: PlatformType;
  displayName: string;
  description: string;
  accountTypeSupported: "business" | "professional" | "consumer" | "bot" | "hybrid";
  capabilities: IntegrationCapability[];
  unsupportedCapabilities: string[];
  requiredScopes: string[];
  consentNotice: string;
  honestLimitationNotice: string;
}

export interface AuthorizationContext {
  userId: string;
  tenantId?: string;
  credentials?: Record<string, string>;
  authCode?: string;
  redirectUri?: string;
}

export interface ConnectionResult {
  success: boolean;
  status: IntegrationStatus;
  accountId?: string;
  accountName?: string;
  grantedScopes?: string[];
  errorMessage?: string;
  connectedAt?: string;
  expiresAt?: string;
}

export interface WebhookVerificationResult {
  isValid: boolean;
  challengeResponse?: string | number;
  reason?: string;
}

export type InputCategory =
  | "url"
  | "message"
  | "email"
  | "social_post"
  | "profile"
  | "job_offer"
  | "company_claim"
  | "qr_code"
  | "payment_screenshot"
  | "invoice"
  | "file_metadata"
  | "phone_number"
  | "unknown";

export interface NormalizedPlatformEvent {
  eventId: string;
  platform: PlatformType;
  sourceAccountId?: string;
  senderHandle?: string;
  senderDisplayName?: string;
  senderIdentifier?: string;
  recipientIdentifier?: string;
  rawText?: string;
  extractedUrls: string[];
  extractedEntities: Record<string, string[]>;
  inputCategory: InputCategory;
  mediaUrls?: string[];
  metadata: Record<string, unknown>;
  receivedAt: string;
  hasExplicitUserConsent: boolean;
}

export interface PlatformIntegration {
  readonly id: string;
  readonly platform: PlatformType;
  readonly displayName: string;

  getCapabilities(): Promise<IntegrationCapabilities>;
  getConnectionStatus(userId: string): Promise<IntegrationStatus>;
  connect(context: AuthorizationContext): Promise<ConnectionResult>;
  disconnect(userId: string): Promise<void>;
  verifyWebhook(request: Request, rawBody?: string): Promise<WebhookVerificationResult>;
  normalizeEvent(rawEvent: unknown): Promise<NormalizedPlatformEvent>;
  testConnection?(userId: string): Promise<{ ok: boolean; message: string; latencyMs: number }>;
}
