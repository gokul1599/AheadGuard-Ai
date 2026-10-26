/**
 * AheadGuard AI — Chrome Extension Configuration
 *
 * Separates production release endpoints from local development hosts.
 */
export const PRODUCTION_BACKEND_URL = "https://aheadguard-ai.vercel.app";
export const DEVELOPMENT_BACKEND_URL = "http://localhost:3000";

/**
 * Default backend URL for production release builds.
 * Never silently points to localhost in production builds.
 */
export const DEFAULT_BACKEND_URL = PRODUCTION_BACKEND_URL;

/**
 * Validates user-configured backend endpoints:
 * 1. Exact production backend: https://aheadguard-ai.vercel.app (port 443 or default)
 * 2. Local development hosts: localhost / 127.0.0.1 (http or https)
 *
 * Rejects unapproved Vercel domains, arbitrary third-party hosts, and URLs with embedded credentials.
 */
export function isValidBackendEndpoint(url?: string): boolean {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    // Reject embedded credentials
    if (parsed.username || parsed.password) return false;

    const host = parsed.hostname.toLowerCase();

    // 1. Official production backend
    if (host === "aheadguard-ai.vercel.app") {
      return parsed.protocol === "https:" && (!parsed.port || parsed.port === "443");
    }

    // 2. Local development endpoints
    if (host === "localhost" || host === "127.0.0.1") {
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    }

    // Reject all other hosts (including other *.vercel.app projects)
    return false;
  } catch {
    return false;
  }
}
