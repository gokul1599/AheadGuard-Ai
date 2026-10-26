/**
 * AheadGuard AI — API Security & Abuse Protection Utilities
 *
 * Provides strict CORS allowlist verification and sliding-window rate limiting.
 */

export const PRODUCTION_DASHBOARD_ORIGIN = "https://aheadguard-ai.vercel.app";

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
 * 1. Exact production dashboard origin (https://aheadguard-ai.vercel.app)
 * 2. Explicit local development origins (http://localhost:*, http://127.0.0.1:*)
 * 3. Approved Chrome Extension IDs matching ALLOWED_EXTENSION_IDS in 32-letter lowercase format.
 *
 * Missing or unrecognized origins are never treated as authorized browser origins.
 */
export function isAllowedOrigin(origin: string | null): boolean {
  if (!origin || typeof origin !== "string") return false;

  // Exact production dashboard origin
  if (origin === PRODUCTION_DASHBOARD_ORIGIN) return true;

  // Explicitly permitted local development origins
  if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;

  // Strict Chrome Extension allowlist: must be syntactically valid AND explicitly whitelisted
  if (origin.startsWith("chrome-extension://")) {
    const extensionId = origin.replace("chrome-extension://", "").replace(/\/.*$/, "").toLowerCase();
    // Reject malformed extension IDs immediately
    if (!/^[a-z]{32}$/.test(extensionId)) {
      return false;
    }
    // Fail safely: only explicitly approved AheadGuard extension IDs are accepted
    const allowed = getAllowedExtensionIds();
    return allowed.has(extensionId);
  }

  return false;
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

export function getClientIp(request: Request): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    const first = forwardedFor.split(",")[0].trim();
    if (first) return first;
  }
  const realIp = request.headers.get("x-real-ip");
  if (realIp) return realIp.trim();
  return "127.0.0.1";
}
