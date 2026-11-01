import { timingSafeEqual, createHash } from "node:crypto";
import { isIP } from "node:net";

/**
 * AheadGuard AI — API Security & Abuse Protection Utilities
 *
 * Provides strict CORS allowlist verification, timing-safe admin authorization,
 * and sliding-window rate limiting.
 */

export const PRODUCTION_DASHBOARD_ORIGIN = "https://aheadguard-ai.vercel.app";
export const CANONICAL_PRODUCTION_ORIGIN = PRODUCTION_DASHBOARD_ORIGIN;

/**
 * Normalizes an origin string into its canonical `scheme://hostname[:port]` representation.
 * - Parses via URL constructor
 * - Extracts exact protocol (lowercase), hostname (lowercase), and port (omits default 80/443)
 * - Returns null for malformed, non-hierarchical, or invalid origins.
 * - Handles custom schemes (e.g. capacitor://localhost, ionic://localhost) safely.
 */
export function normalizeOrigin(origin: string | null | undefined): string | null {
  if (!origin || typeof origin !== "string") return null;
  const trimmed = origin.trim();
  if (!trimmed || trimmed === "null") return null;

  // Reject wildcards, whitespace, or relative paths immediately
  if (trimmed === "*" || /\s/.test(trimmed) || trimmed.startsWith("/")) {
    return null;
  }

  // Handle Chrome extension origins: chrome-extension://<32-letter-id>
  if (trimmed.startsWith("chrome-extension://")) {
    const rawId = trimmed.replace("chrome-extension://", "").replace(/\/.*$/, "").toLowerCase();
    return /^[a-z]{32}$/.test(rawId) ? `chrome-extension://${rawId}` : null;
  }

  try {
    const parsed = new URL(trimmed);
    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();
    const port = parsed.port;

    // Supported schemes: http, https, capacitor, ionic
    if (!["http:", "https:", "capacitor:", "ionic:"].includes(protocol)) {
      return null;
    }

    if (!hostname) return null;

    // Reject wildcards or invalid characters in host
    if (hostname.includes("*") || hostname.includes("/") || hostname.includes("\\")) {
      return null;
    }

    // Default ports: omit :80 for http and :443 for https
    const isDefaultPort = (protocol === "http:" && port === "80") || (protocol === "https:" && port === "443");
    const formattedPort = port && !isDefaultPort ? `:${port}` : "";

    return `${protocol}//${hostname}${formattedPort}`;
  } catch {
    return null;
  }
}

/**
 * Retrieves the set of explicitly approved web and app origins from:
 * 1. The canonical production origin: https://aheadguard-ai.vercel.app
 * 2. Explicitly configured ALLOWED_APP_ORIGINS (comma-separated list from environment)
 * 3. Environment variables VERCEL_URL and NEXT_PUBLIC_APP_URL
 */
export function getAllowedOrigins(): Set<string> {
  const allowed = new Set<string>();

  // 1. Canonical production origin
  const canonical = normalizeOrigin(PRODUCTION_DASHBOARD_ORIGIN);
  if (canonical) allowed.add(canonical);

  // 2. Origins from ALLOWED_APP_ORIGINS environment variable
  const rawAppOrigins = process.env.ALLOWED_APP_ORIGINS || "";
  if (rawAppOrigins.trim()) {
    const splitOrigins = rawAppOrigins
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    for (const raw of splitOrigins) {
      const normalized = normalizeOrigin(raw);
      if (normalized) {
        allowed.add(normalized);
      }
    }
  }

  // 3. VERCEL_URL support (set by Vercel in preview/branch deployments)
  if (process.env.VERCEL_URL) {
    const vercelOrigin = normalizeOrigin(`https://${process.env.VERCEL_URL}`);
    if (vercelOrigin) allowed.add(vercelOrigin);
  }

  // 4. NEXT_PUBLIC_APP_URL support
  if (process.env.NEXT_PUBLIC_APP_URL) {
    const appUrlOrigin = normalizeOrigin(process.env.NEXT_PUBLIC_APP_URL);
    if (appUrlOrigin) allowed.add(appUrlOrigin);
  }

  return allowed;
}

/**
 * Retrieves the set of explicitly approved Chrome Extension IDs from the environment.
 * Only explicitly whitelisted 32-letter lowercase IDs are trusted.
 * If unset or invalid, fails safely by permitting no extension origins.
 */
export function getAllowedExtensionIds(): Set<string> {
  const raw = process.env.ALLOWED_EXTENSION_IDS || process.env.AHEADGUARD_EXTENSION_ID || "";
  const validIds = raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[a-z]{32}$/.test(s));
  return new Set(validIds);
}

/**
 * Validates request Origin against the strict AheadGuard allowlist:
 * 1. Exact canonical production dashboard origin (https://aheadguard-ai.vercel.app)
 * 2. Explicitly configured ALLOWED_APP_ORIGINS (e.g. iOS WebViews, custom app schemes)
 * 3. Approved Chrome Extension IDs matching ALLOWED_EXTENSION_IDS in 32-letter lowercase format.
 * 4. Explicit local development origins (http://localhost:*, http://127.0.0.1:*)
 * 5. Same-Origin verification: If request is provided, safely checks if origin matches request host.
 *
 * Requirements:
 * - Scheme, hostname, and port are normalized and compared exactly.
 * - Wildcard origins are NEVER permitted.
 * - Arbitrary origin reflection is NEVER permitted.
 * - "null" origin is strictly rejected.
 * - Missing origin is handled safely (not treated as an authorized cross-origin browser).
 */
export function isAllowedOrigin(origin: string | null | undefined, request?: Request): boolean {
  if (!origin || typeof origin !== "string") return false;
  if (origin === "null") return false; // Strict rejection of null origins

  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;

  // 1. Check Chrome Extension allowlist
  if (normalized.startsWith("chrome-extension://")) {
    const extensionId = normalized.replace("chrome-extension://", "").toLowerCase();
    const allowedExtensions = getAllowedExtensionIds();
    return allowedExtensions.has(extensionId);
  }

  // 2. Check explicitly configured and canonical origins
  const allowedSet = getAllowedOrigins();
  if (allowedSet.has(normalized)) {
    return true;
  }

  // 3. Localhost / Loopback development origins
  if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(normalized)) {
    return true;
  }

  // 4. Same-origin comparison if request is available:
  // If the browser is on the same host that is serving the request (e.g. a preview deployment or custom domain)
  if (request) {
    const hostHeader = request.headers.get("x-forwarded-host") || request.headers.get("host");
    const protoHeader = request.headers.get("x-forwarded-proto") || "https";
    if (hostHeader) {
      const sameOrigin = normalizeOrigin(`${protoHeader}://${hostHeader}`);
      if (sameOrigin && sameOrigin === normalized) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Generates CORS headers for authorized origins.
 * Never uses wildcard "*". Only reflects explicitly validated, normalized origins.
 */
export function createCorsHeaders(request: Request, allowedMethods: string = "GET, POST, OPTIONS"): Record<string, string> {
  const origin = request.headers.get("origin");
  if (origin && isAllowedOrigin(origin, request)) {
    const normalized = normalizeOrigin(origin) || origin;
    return {
      "Access-Control-Allow-Origin": normalized,
      "Access-Control-Allow-Methods": allowedMethods,
      "Access-Control-Allow-Headers": "Content-Type, Accept, Authorization, X-Requested-With",
      "Vary": "Origin",
    };
  }
  return {
    "Vary": "Origin",
  };
}

/**
 * Returns a structured JSON HTTP 403 Response for rejected CORS origins.
 * Provides safe, actionable diagnostic information without leaking secrets.
 */
export function createCorsForbiddenResponse(request: Request, reason: string = "Origin is not authorized by AheadGuard security policy."): Response {
  void request;
  return new Response(
    JSON.stringify({
      error: `CORS origin not allowed: ${reason}`,
      code: "CORS_ORIGIN_DENIED",
      hint: "Your browser or app origin is not authorized to access AheadGuard API. For iOS WebViews or custom domains, configure ALLOWED_APP_ORIGINS.",
    }),
    {
      status: 403,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Vary": "Origin",
      },
    }
  );
}

/**
 * In-memory sliding-window IP rate limiter for public abuse prevention.
 * Limit: 20 investigations per 60 seconds per IP.
 * Burst: max 5 requests per 5 seconds per IP.
 *
 * NOTE: Operates per compute container instance. For globally synchronized
 * multi-region rate limiting across all edge nodes, an external distributed store
 * (such as Upstash Redis or Vercel KV with @upstash/ratelimit) should be configured.
 */
interface RateLimitRecord {
  timestamps: number[];
}

const rateLimitMap = new Map<string, RateLimitRecord>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 60 seconds
const RATE_LIMIT_MAX_REQUESTS = 20; // 20 requests per minute
const RATE_LIMIT_BURST_WINDOW_MS = 5 * 1000; // 5 seconds
const RATE_LIMIT_BURST_MAX = 5; // max 5 per 5 seconds

export function checkRateLimit(ip: string): {
  allowed: boolean;
  retryAfter?: number;
  limit: number;
  remaining: number;
} {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { timestamps: [] };

  // Remove timestamps older than the sliding window
  record.timestamps = record.timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

  // Check burst limit (last 5 seconds)
  const recentBurst = record.timestamps.filter((t) => now - t < RATE_LIMIT_BURST_WINDOW_MS);
  if (recentBurst.length >= RATE_LIMIT_BURST_MAX) {
    const oldestBurst = recentBurst[0] || now;
    const retryAfter = Math.max(1, Math.ceil((RATE_LIMIT_BURST_WINDOW_MS - (now - oldestBurst)) / 1000));
    return { allowed: false, retryAfter, limit: RATE_LIMIT_MAX_REQUESTS, remaining: 0 };
  }

  // Check window limit (last 60 seconds)
  if (record.timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    const oldest = record.timestamps[0];
    const retryAfter = Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldest)) / 1000));
    return { allowed: false, retryAfter, limit: RATE_LIMIT_MAX_REQUESTS, remaining: 0 };
  }

  // Record timestamp and persist
  record.timestamps.push(now);
  rateLimitMap.set(ip, record);

  // Periodic eviction of stale records if map grows large
  if (rateLimitMap.size > 2000) {
    for (const [key, val] of rateLimitMap.entries()) {
      if (val.timestamps.length === 0 || now - val.timestamps[val.timestamps.length - 1] > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.delete(key);
      }
    }
  }

  return {
    allowed: true,
    limit: RATE_LIMIT_MAX_REQUESTS,
    remaining: Math.max(0, RATE_LIMIT_MAX_REQUESTS - record.timestamps.length),
  };
}

export function resetRateLimitForTesting() {
  rateLimitMap.clear();
}

/**
 * Normalizes an IP string, stripping whitespace and mapping IPv4-mapped IPv6 (::ffff:x.x.x.x)
 * to standard IPv4 so dual-stack clients share the same rate-limit bucket.
 */
export function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  if (trimmed.startsWith("::ffff:") && isIP(trimmed.substring(7)) === 4) {
    return trimmed.substring(7);
  }
  return trimmed;
}

/**
 * Resolves the incoming client IP address for rate limiting.
 *
 * PROXY TRUST BOUNDARY & SECURITY ENFORCEMENT:
 * - Production Deployment (Vercel): Vercel's edge network reverse proxy terminates
 *   the client TCP connection and unconditionally sets `x-real-ip` to the connecting client's
 *   socket address. Downstream clients cannot forge `x-real-ip` on Vercel because the edge proxy
 *   overwrites or strips any incoming client value.
 * - Anti-Spoofing & Unsafe Fallback Elimination:
 *   Forwarding headers like `x-forwarded-for` are fundamentally untrusted because arbitrary external
 *   clients can supply spoofed values. AheadGuard NEVER falls back to unverified `x-forwarded-for`
 *   headers when `x-real-ip` is missing or malformed.
 *   Treating client-supplied `x-forwarded-for` as authoritative would allow attackers to rotate
 *   forged IP headers and completely bypass rate limiting.
 * - Missing / Malformed Canonical IP Fallback:
 *   If `x-real-ip` is absent, empty, whitespace-only, or syntactically invalid (e.g. malformed IP),
 *   the request safely defaults to "127.0.0.1". In production, all unverified requests share this single
 *   rate-limit bucket, guaranteeing that an attacker cannot evade throttling by rotating forged headers.
 * - Syntactic Validation & Dual-Stack Normalization:
 *   Every candidate IP is validated via Node.js `net.isIP()`. IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`)
 *   are normalized to IPv4 to prevent dual-stack rate-limit bucket splitting.
 * - In-Memory Limitation: The sliding window limiter is instance-local per compute container.
 */
/**
 * Inspects whether the incoming request contains an authoritative, verified canonical client IP
 * from the trusted edge reverse proxy header (`x-real-ip`).
 * Returns true if `x-real-ip` is present and valid IPv4 or IPv6; false if missing or malformed.
 */
export function hasTrustedClientIp(request: Request): boolean {
  const realIp = request.headers.get("x-real-ip");
  if (!realIp) return false;
  return isIP(realIp.trim()) !== 0;
}

export function getClientIp(request: Request): string {
  // 1. Check canonical platform header (populated and overwritten by Vercel edge reverse proxy from TCP socket)
  const realIp = request.headers.get("x-real-ip");
  if (realIp) {
    const trimmed = realIp.trim();
    if (isIP(trimmed)) {
      return normalizeIp(trimmed);
    }
  }

  // 2. Safe fallback: Never trust unverified x-forwarded-for headers to prevent rotation-based rate limit bypass.
  // In local development, direct socket connections, or environments without a trusted edge proxy,
  // all unverified requests map to the safe loopback bucket.
  return "127.0.0.1";
}

/**
 * Validates whether the incoming request contains an authorized Administrator bearer token.
 * Enforces RFC 6750 Section 2.1 Bearer credential syntax and RFC 9110 Section 11.1
 * case-insensitive authentication scheme names (e.g. "Bearer", "bearer", "BEARER", "bEaReR").
 *
 * Requirements enforced:
 * - Scheme must be "Bearer" (case-insensitive) separated by one or more ASCII spaces (1*SP).
 * - Tabs (\t) are strictly rejected as scheme-token separators per RFC 6750 grammar.
 * - Credentials must strictly match RFC 6750 b64token syntax: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 * - Token length is bounded to max 512 characters; header length bounded to max 1,024 characters.
 * - Fixed-size 32-byte SHA-256 digests are computed and compared using crypto.timingSafeEqual.
 *   Only this fixed-size digest comparison is timing-safe (no end-to-end request timing invariance is claimed).
 * - Fails safely (fail-closed) if AHEADGUARD_ADMIN_KEY is unconfigured, empty, or whitespace-only.
 */
export function verifyAdminAuth(request: Request): boolean {
  const adminKey = process.env.AHEADGUARD_ADMIN_KEY;
  if (!adminKey || adminKey.trim().length === 0) {
    return false;
  }

  const authHeader = request.headers.get("authorization");
  if (!authHeader || authHeader.length > 1024) {
    return false;
  }

  // Reject control characters or newlines (CR, LF, NUL, tabs, etc.) per RFC 6750 Section 2.1
  if (/[\r\n\t\x00-\x1f\x7f]/.test(authHeader)) {
    return false;
  }

  // Parse scheme and token: scheme must be strictly case-insensitive "Bearer" starting at index 0 (no leading spaces),
  // separated by 1 or more ASCII spaces (1*SP per RFC 6750)
  const match = authHeader.match(/^bearer +(.*)$/i);
  if (!match) {
    return false;
  }

  const providedToken = match[1];
  // Bound token length to max 512 characters to protect against CPU/memory exhaustion on malformed payloads
  if (!providedToken || providedToken.length > 512) {
    return false;
  }

  // RFC 6750 Section 2.1 b64token grammar:
  // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  // Enforces valid character set and strict trailing-only padding '=' placement
  const b64TokenRegex = /^[a-zA-Z0-9\-._~+/]+=*$/;
  if (!b64TokenRegex.test(providedToken)) {
    return false;
  }

  const adminHash = createHash("sha256").update(adminKey.trim(), "utf8").digest();
  const providedHash = createHash("sha256").update(providedToken, "utf8").digest();

  return timingSafeEqual(adminHash, providedHash);
}
