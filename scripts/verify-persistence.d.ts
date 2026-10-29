export interface PersistenceVerificationOptions {
  baseUrl?: string;
  adminKey?: string;
  testAdminKey?: string;
  confirmOptIn?: boolean;
  isProd?: boolean;
  allowedOrigins?: string[];
  timeoutMs?: number;
  fetchFn?: typeof fetch;
  logger?: {
    log: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
}

export interface PersistenceVerificationResult {
  success: boolean;
  optedIn: boolean;
  investigationId?: string;
  marker?: string;
  error?: string;
  details?: {
    postStatus?: number;
    unauthGetStatus?: number;
    authGetStatus?: number;
    storageMode?: string;
    persisted?: boolean;
    markerVerified?: boolean;
  };
}

export const CANONICAL_PRODUCTION_ORIGIN: string;
export function generatePersistenceMarker(): string;
export function buildHarmlessPersistencePayload(marker: string): { input: string; analysisMode: string };
export function isLoopbackOrigin(url: URL): boolean;
export function validateTargetOrigin(rawUrl?: string, isProdMode?: boolean, allowedOrigins?: string[]): { valid: boolean; origin?: string; error?: string };
export function sanitizeSecrets(text: string, secrets?: string[]): string;
export function parseJsonResponse(bodyText: string, status: number, stepName: string): unknown;
export function verifyProductionPersistence(options?: PersistenceVerificationOptions): Promise<PersistenceVerificationResult>;
export function runCli(argv?: string[]): Promise<number>;
