export interface PersistenceVerificationOptions {
  baseUrl?: string;
  adminKey?: string;
  confirmOptIn?: boolean;
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
  };
}

export function generatePersistenceMarker(): string;
export function buildHarmlessPersistencePayload(marker: string): { input: string; analysisMode: string };
export function sanitizeSecrets(text: string, secrets?: string[]): string;
export function safeParseJsonResponse(response: Response, stepName: string, secrets?: string[]): Promise<unknown>;
export function verifyProductionPersistence(options?: PersistenceVerificationOptions): Promise<PersistenceVerificationResult>;
export function runCli(argv?: string[]): Promise<number>;
