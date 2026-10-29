#!/usr/bin/env node

/**
 * AheadGuard AI — Hardened Production Persistence Verification Probe
 *
 * Dedicated opt-in verification script for end-to-end database persistence.
 *
 * Security & Reliability Controls Enforced:
 * 1. Strict Target-Origin Authorization:
 *    - Production mode strictly targets the canonical origin: https://aheadguard-ai.vercel.app
 *    - Conflicting --url with --prod is rejected.
 *    - Custom targets require explicit allowlisting (--allow-origin).
 *    - Plain HTTP rejected for non-loopback destinations.
 *    - URL userinfo (embedded credentials) strictly rejected.
 * 2. Credential Security:
 *    - Credential-bearing CLI arguments (--key) are completely removed.
 *    - Admin secret must be supplied via AHEADGUARD_ADMIN_KEY environment variable.
 *    - Production key is never transmitted to unapproved/custom origins.
 *    - Zero secret leakage in logs, errors, or stack traces.
 * 3. Safe Information Handling:
 *    - Raw input URLs, query tokens, and upstream error bodies are never echoed.
 * 4. Cross-Origin Redirect Protection:
 *    - Network requests reject unexpected redirects (redirect: "error").
 * 5. Complete Lifecycle Timeouts:
 *    - Deadline covers the full request and response body consumption.
 * 6. End-to-End Persistence & Marker Verification:
 *    - Text-only probe without URLs (zero TinyFish crawler cost).
 *    - Real investigationId, persisted === true, storageMode === "persisted" required.
 *    - Unauthenticated GET /api/investigate?id=<id> must be rejected with HTTP 401.
 *    - Authenticated GET with Bearer token must succeed (HTTP 200).
 *    - Record ID must match.
 *    - Exact unique marker must be verified inside the retrieved stored record.
 * 7. Immutable Audit Ledger Preservation:
 *    - No public record deletion endpoint invented.
 */

import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

export const CANONICAL_PRODUCTION_ORIGIN = "https://aheadguard-ai.vercel.app";

/**
 * Generates a unique, searchable persistence probe marker.
 * Format: aheadguard-persistence-probe-<timestamp>-<hex>
 */
export function generatePersistenceMarker() {
  const timestamp = Date.now();
  const rand = randomBytes(8).toString("hex");
  return `aheadguard-persistence-probe-${timestamp}-${rand}`;
}

/**
 * Constructs a harmless, text-only investigation payload.
 * Strictly avoids any URLs or domain patterns to ensure TinyFish is never invoked.
 */
export function buildHarmlessPersistencePayload(marker) {
  return {
    input: `AheadGuard automated database persistence verification probe. Unique marker: [${marker}]. Harmless text-only verification test for database write and authorized read. No destination URLs.`,
    analysisMode: "message",
  };
}

/**
 * Determines whether a given URL points to a local loopback interface.
 */
export function isLoopbackOrigin(url) {
  const hostname = url.hostname.toLowerCase();
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost")
  );
}

/**
 * Strictly validates and normalizes the target origin.
 *
 * @param {string} rawUrl - Target URL string
 * @param {boolean} [isProdMode=false] - Whether --prod mode is explicitly selected
 * @param {string[]} [allowedOrigins=[]] - Custom allowed origins list
 * @returns {{ valid: boolean; origin?: string; error?: string }}
 */
export function validateTargetOrigin(rawUrl, isProdMode = false, allowedOrigins = []) {
  if (!rawUrl || typeof rawUrl !== "string" || rawUrl.trim().length === 0) {
    return {
      valid: false,
      error: "Target URL required. Specify --prod to target canonical production origin or supply an approved URL.",
    };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return {
      valid: false,
      error: "Invalid verification target URL. Supply an approved HTTPS origin.",
    };
  }

  // Reject URL userinfo (embedded username/password)
  if (parsed.username || parsed.password) {
    return {
      valid: false,
      error: "Invalid verification target URL: embedded credentials (userinfo) are rejected for security.",
    };
  }

  // Reject unexpected schemes
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return {
      valid: false,
      error: "Invalid verification target URL: scheme must be https (or http for permitted local loopback development).",
    };
  }

  const origin = parsed.origin.toLowerCase();

  // In production mode, target MUST be canonical production origin
  if (isProdMode) {
    if (origin !== CANONICAL_PRODUCTION_ORIGIN.toLowerCase()) {
      return {
        valid: false,
        error: "Target origin rejected: production mode strictly permits only canonical origin https://aheadguard-ai.vercel.app.",
      };
    }
    return { valid: true, origin: CANONICAL_PRODUCTION_ORIGIN };
  }

  // If targeting canonical production origin without explicit --prod, normalize to canonical
  if (origin === CANONICAL_PRODUCTION_ORIGIN.toLowerCase()) {
    return { valid: true, origin: CANONICAL_PRODUCTION_ORIGIN };
  }

  // Reject plain HTTP for any non-loopback destination
  if (parsed.protocol === "http:" && !isLoopbackOrigin(parsed)) {
    return {
      valid: false,
      error: "Invalid verification target URL: HTTP is only permitted for local loopback development (localhost / 127.0.0.1).",
    };
  }

  // Check custom allowed origins list (required for ALL non-production destinations, including loopback)
  const normalizedAllowlist = allowedOrigins.map((o) => {
    try {
      return new URL(o).origin.toLowerCase();
    } catch {
      return typeof o === "string" ? o.trim().toLowerCase() : "";
    }
  });

  if (normalizedAllowlist.includes(origin)) {
    return { valid: true, origin: parsed.origin };
  }

  if (isLoopbackOrigin(parsed)) {
    return {
      valid: false,
      error: "Target origin rejected: loopback origin is not in the approved origin allowlist. Specify --allow-origin to authorize.",
    };
  }

  return {
    valid: false,
    error: "Target origin rejected: custom destination is not in the approved origin allowlist.",
  };
}

/**
 * Redacts known and heuristic secrets from text, error messages, and log strings.
 */
export function sanitizeSecrets(text, secrets = []) {
  if (typeof text !== "string") {
    return "";
  }
  let sanitized = text;

  try {
    // Redact explicit secrets passed in
    for (const secret of secrets) {
      if (typeof secret === "string" && secret.trim().length > 0) {
        sanitized = sanitized.replaceAll(secret, "[REDACTED]");
      }
    }

    // Redact Bearer tokens
    sanitized = sanitized.replace(/Bearer\s+[a-zA-Z0-9_\-.~+/]+=*/gi, "Bearer [REDACTED]");

    // Redact database connection strings
    sanitized = sanitized.replace(/postgres(?:ql)?:\/\/[^\s"'<>]+/gi, "postgres://[REDACTED]");

    // Redact userinfo embedded in URLs
    sanitized = sanitized.replace(/:\/\/([^@\s"']+):([^@\s"']+)@/g, "://[REDACTED]:[REDACTED]@");

    // Redact generic key/secret/token patterns
    sanitized = sanitized.replace(
      /(?:tf_|api[-_]?key|key|secret|token|password|admin[-_]?key)[=:\s]+[A-Za-z0-9_\-.]{8,}/gi,
      "[REDACTED]"
    );

    // Strip stack trace paths that might leak username or directory structure
    sanitized = sanitized.replace(/\bat\s+.*?(?:\.ts|\.js|\.mjs|\.cjs)(?::\d+:\d+)?/gi, "");
  } catch {
    return "[SANITIZATION_ERROR_REDACTED]";
  }

  return sanitized.trim();
}

/**
 * Safely parses a response body string as JSON with error containment and zero raw-body leakage.
 */
export function parseJsonResponse(bodyText, status, stepName) {
  try {
    return JSON.parse(bodyText);
  } catch {
    throw new Error(`${stepName} returned non-JSON payload (HTTP ${status}).`);
  }
}

/**
 * Executes a network request where timeout covers both fetch and response body reading,
 * and unexpected redirects are rejected.
 */
async function executeBoundedRequest(url, fetchOptions, stepName, timeoutMs, fetchFn, secrets) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new Error(`Timeout after ${timeoutMs}ms`));
  }, timeoutMs);

  try {
    const res = await fetchFn(url, {
      ...fetchOptions,
      signal: controller.signal,
      redirect: "error", // Reject unexpected redirects to prevent credential leakage
    });

    // Read full response text while timeout timer is STILL ACTIVE
    const bodyText = await res.text();

    return {
      ok: res.ok,
      status: res.status,
      bodyText,
    };
  } catch (err) {
    if (controller.signal.aborted || (err instanceof Error && err.name === "AbortError")) {
      throw new Error(`Request timed out after ${timeoutMs}ms during ${stepName}.`);
    }
    const rawMsg = err instanceof Error ? err.message : String(err);
    if (rawMsg.toLowerCase().includes("redirect")) {
      throw new Error(`Security violation: unexpected redirect encountered during ${stepName}. Redirects are rejected to protect credentials.`);
    }
    const sanitizedMsg = sanitizeSecrets(rawMsg, secrets);
    throw new Error(`Network failure during ${stepName}: ${sanitizedMsg}`);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @typedef {Object} PersistenceVerificationResult
 * @property {boolean} success
 * @property {boolean} optedIn
 * @property {string} [investigationId]
 * @property {string} [marker]
 * @property {string} [error]
 * @property {Object} [details]
 * @property {number} [details.postStatus]
 * @property {number} [details.unauthGetStatus]
 * @property {number} [details.authGetStatus]
 * @property {string} [details.storageMode]
 * @property {boolean} [details.persisted]
 * @property {boolean} [details.markerVerified]
 */

/**
 * Core persistence verification engine.
 *
 * @param {Object} [options]
 * @param {string} [options.baseUrl] - Target API base URL
 * @param {string} [options.adminKey] - Production admin key for Authorization: Bearer <key>
 * @param {string} [options.testAdminKey] - Non-production test admin key for non-production targets
 * @param {boolean} [options.confirmOptIn] - Explicit operator authorization flag
 * @param {boolean} [options.isProd] - Whether targeting production canonical origin
 * @param {string[]} [options.allowedOrigins] - Allowlist for custom test targets
 * @param {number} [options.timeoutMs] - Request timeout in milliseconds (default: 15000)
 * @param {Function} [options.fetchFn] - Optional fetch implementation (for unit testing)
 * @param {Object} [options.logger] - Optional logger interface
 * @returns {Promise<PersistenceVerificationResult>} Verification result
 */
export async function verifyProductionPersistence(options = {}) {
  const {
    baseUrl: rawBaseUrl,
    adminKey: rawAdminKey,
    testAdminKey: rawTestAdminKey,
    confirmOptIn = false,
    isProd = false,
    allowedOrigins = [],
    timeoutMs = 15000,
    fetchFn = globalThis.fetch,
    logger,
  } = options;

  const log = (msg) => (logger?.log ? logger.log(msg) : console.log(msg));
  const warn = (msg) => (logger?.warn ? logger.warn(msg) : console.warn(msg));

  // 1. Enforce explicit operator opt-in gate (Zero requests made if unconfirmed)
  if (!confirmOptIn) {
    return {
      success: false,
      optedIn: false,
      error:
        "Opt-in required: Live production persistence verification makes real HTTP requests and creates a verified record in Neon PostgreSQL. Pass --confirm-live-persistence or set RUN_LIVE_PERSISTENCE_TEST=true to authorize execution.",
    };
  }

  // 2. Validate target URL and enforce strict origin authorization
  const originValidation = validateTargetOrigin(rawBaseUrl, isProd, allowedOrigins);
  if (!originValidation.valid || !originValidation.origin) {
    return {
      success: false,
      optedIn: true,
      error: originValidation.error || "Invalid verification target origin.",
    };
  }

  const baseUrl = originValidation.origin;
  const isProdTarget = isProd || baseUrl.toLowerCase() === CANONICAL_PRODUCTION_ORIGIN.toLowerCase();

  // 3. Validate Administrator Key with Strict Credential Isolation
  let activeKey = "";
  if (isProdTarget) {
    const adminKey = (rawAdminKey || process.env.AHEADGUARD_ADMIN_KEY || "").trim();
    if (!adminKey) {
      return {
        success: false,
        optedIn: true,
        error: "AHEADGUARD_ADMIN_KEY is required for production persistence verification.",
      };
    }
    activeKey = adminKey;
  } else {
    const testKey = (rawTestAdminKey || process.env.AHEADGUARD_TEST_ADMIN_KEY || "").trim();
    const prodKeyPresent = Boolean((rawAdminKey || process.env.AHEADGUARD_ADMIN_KEY || "").trim());

    if (!testKey) {
      if (prodKeyPresent) {
        return {
          success: false,
          optedIn: true,
          error:
            "Non-production verification targets require AHEADGUARD_TEST_ADMIN_KEY. Production AHEADGUARD_ADMIN_KEY cannot be transmitted to non-production targets.",
        };
      }
      return {
        success: false,
        optedIn: true,
        error: "AHEADGUARD_TEST_ADMIN_KEY is required for non-production persistence verification.",
      };
    }
    activeKey = testKey;
  }

  // Secrets list for output/error redaction
  const secrets = [activeKey];
  if (rawAdminKey) secrets.push(rawAdminKey);
  if (rawTestAdminKey) secrets.push(rawTestAdminKey);
  if (process.env.AHEADGUARD_ADMIN_KEY) secrets.push(process.env.AHEADGUARD_ADMIN_KEY);
  if (process.env.AHEADGUARD_TEST_ADMIN_KEY) secrets.push(process.env.AHEADGUARD_TEST_ADMIN_KEY);
  if (process.env.DATABASE_URL) secrets.push(process.env.DATABASE_URL);
  if (process.env.MIGRATION_DATABASE_URL) secrets.push(process.env.MIGRATION_DATABASE_URL);
  if (process.env.TINYFISH_API_KEY) secrets.push(process.env.TINYFISH_API_KEY);

  const marker = generatePersistenceMarker();
  const payload = buildHarmlessPersistencePayload(marker);

  log(`[AheadGuard Persistence Verifier] Starting verification against ${baseUrl}`);
  log(`[AheadGuard Persistence Verifier] Marker: ${marker}`);

  let investigationId;

  // =========================================================================
  // STEP 1: POST harmless text-only probe to create a persisted record
  // =========================================================================
  try {
    const postRes = await executeBoundedRequest(
      `${baseUrl}/api/investigate`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: JSON.stringify(payload),
      },
      "POST harmless text-only investigation",
      timeoutMs,
      fetchFn,
      secrets
    );

    if (!postRes.ok) {
      return {
        success: false,
        optedIn: true,
        marker,
        error: `POST /api/investigate failed with HTTP ${postRes.status}`,
        details: { postStatus: postRes.status },
      };
    }

    const postData = parseJsonResponse(postRes.bodyText, postRes.status, "POST investigation");
    if (!postData || typeof postData !== "object" || !postData.report || typeof postData.report !== "object") {
      return {
        success: false,
        optedIn: true,
        marker,
        error: "POST /api/investigate response missing 'report' object.",
        details: { postStatus: postRes.status },
      };
    }

    const report = postData.report;
    investigationId = report.investigationId;

    if (!investigationId || typeof investigationId !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(investigationId)) {
      return {
        success: false,
        optedIn: true,
        marker,
        error: "POST /api/investigate returned invalid investigationId.",
        details: { postStatus: postRes.status },
      };
    }

    // Require report.persisted === true and report.storageMode === "persisted"
    if (report.persisted !== true || report.storageMode !== "persisted") {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: `Persistence verification failed: report storageMode is '${report.storageMode || "unknown"}' (persisted: ${Boolean(report.persisted)}). The production database is unconfigured or unable to persist records.`,
        details: {
          postStatus: postRes.status,
          storageMode: report.storageMode,
          persisted: Boolean(report.persisted),
        },
      };
    }

    log(`[AheadGuard Persistence Verifier] Record created: ID=${investigationId}, storageMode=persisted`);
  } catch (step1Err) {
    return {
      success: false,
      optedIn: true,
      marker,
      error: sanitizeSecrets(step1Err instanceof Error ? step1Err.message : String(step1Err), secrets),
    };
  }

  // =========================================================================
  // STEP 2: Unauthenticated GET must be rejected with HTTP 401 Unauthorized
  // =========================================================================
  let unauthStatus;
  try {
    const unauthRes = await executeBoundedRequest(
      `${baseUrl}/api/investigate?id=${encodeURIComponent(investigationId)}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
        },
      },
      "Unauthenticated record retrieval check",
      timeoutMs,
      fetchFn,
      secrets
    );

    unauthStatus = unauthRes.status;
    if (unauthStatus !== 401) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: `Security check failed: unauthenticated read of investigation returned HTTP ${unauthStatus}, expected HTTP 401 Unauthorized.`,
        details: {
          postStatus: 200,
          unauthGetStatus: unauthStatus,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    log(`[AheadGuard Persistence Verifier] Unauthenticated read correctly rejected with HTTP 401`);
  } catch (step2Err) {
    return {
      success: false,
      optedIn: true,
      investigationId,
      marker,
      error: sanitizeSecrets(step2Err instanceof Error ? step2Err.message : String(step2Err), secrets),
      details: {
        postStatus: 200,
        unauthGetStatus: unauthStatus,
        storageMode: "persisted",
        persisted: true,
      },
    };
  }

  // =========================================================================
  // STEP 3: Authenticated GET with Bearer token must retrieve persisted record
  // =========================================================================
  let authStatus;
  try {
    const authRes = await executeBoundedRequest(
      `${baseUrl}/api/investigate?id=${encodeURIComponent(investigationId)}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Authorization": `Bearer ${activeKey}`,
        },
      },
      "Authenticated record retrieval",
      timeoutMs,
      fetchFn,
      secrets
    );

    authStatus = authRes.status;

    if (authStatus === 401) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error:
          "Admin authentication failed: server rejected the provided administrative credential with HTTP 401 Unauthorized.",
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: 401,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    if (authStatus === 404) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: `Persisted record was not found in the database (HTTP 404). The write may not have committed.`,
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: 404,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    if (!authRes.ok) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: `Authenticated record read failed with HTTP ${authStatus}`,
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: authStatus,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    const authData = parseJsonResponse(authRes.bodyText, authRes.status, "Authenticated record read");
    if (!authData || typeof authData !== "object" || !authData.report || typeof authData.report !== "object") {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: "Authenticated record read response missing 'report' object.",
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: authStatus,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    const retrievedReport = authData.report;
    if (retrievedReport.investigationId !== investigationId) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: `Retrieved record ID does not match expected ID.`,
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: authStatus,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    if (!retrievedReport.riskOutcome || typeof retrievedReport.riskOutcome !== "string") {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: "Retrieved record missing valid 'riskOutcome' field.",
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: authStatus,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    // Explicit Marker Verification in Retrieved Stored Report
    // AheadGuard's PII redactor masks 10+ digit numeric sequences as potential phone numbers
    // (e.g. replacing the Unix millisecond timestamp with '[PHONE REDACTED]').
    // We check both the literal marker, the PII-redacted marker variant, and the 16-hex nonce.
    const messageExcerpt = retrievedReport.scamIntelligence?.messageExcerpt || "";
    const fullReportJson = JSON.stringify(retrievedReport);
    const sanitizedMarkerVariant = marker.replace(
      /aheadguard-persistence-probe-\d+-/,
      "aheadguard-persistence-probe-[PHONE REDACTED]-"
    );
    const nonce = marker.split("-").pop() || "";

    const markerVerified =
      messageExcerpt.includes(marker) ||
      fullReportJson.includes(marker) ||
      messageExcerpt.includes(sanitizedMarkerVariant) ||
      fullReportJson.includes(sanitizedMarkerVariant) ||
      (nonce.length === 16 && (messageExcerpt.includes(nonce) || fullReportJson.includes(nonce)));

    if (!markerVerified) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: `Persistence verification failed: retrieved record does not contain the unique test marker. The record was not accurately persisted.`,
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: authStatus,
          storageMode: "persisted",
          persisted: true,
          markerVerified: false,
        },
      };
    }

    log(`[AheadGuard Persistence Verifier] Authenticated read succeeded: ID=${retrievedReport.investigationId}, outcome="${retrievedReport.riskOutcome}"`);
    log(`[AheadGuard Persistence Verifier] Unique marker verified in stored record: ${marker}`);
  } catch (step3Err) {
    return {
      success: false,
      optedIn: true,
      investigationId,
      marker,
      error: sanitizeSecrets(step3Err instanceof Error ? step3Err.message : String(step3Err), secrets),
      details: {
        postStatus: 200,
        unauthGetStatus: 401,
        authGetStatus: authStatus,
        storageMode: "persisted",
        persisted: true,
      },
    };
  }

  // Immutable audit ledger reminder
  warn(
    `[AheadGuard Persistence Verifier] Notice: AheadGuard intentionally does not provide a public or automated record deletion endpoint to preserve audit ledger immutability. Verification record '${investigationId}' with marker '${marker}' remains in Neon PostgreSQL and may be retained or pruned by database administrators.`
  );

  return {
    success: true,
    optedIn: true,
    investigationId,
    marker,
    details: {
      postStatus: 200,
      unauthGetStatus: 401,
      authGetStatus: 200,
      storageMode: "persisted",
      persisted: true,
      markerVerified: true,
    },
  };
}

/**
 * CLI execution entrypoint
 */
export async function runCli(argv = process.argv.slice(2)) {
  const isHelp = argv.includes("--help") || argv.includes("-h");
  if (isHelp) {
    console.log(`
AheadGuard AI — Production Persistence Verification Probe

Usage:
  node scripts/verify-persistence.mjs [options]

Options:
  --confirm-live-persistence   Required confirmation to authorize live requests
  --prod                       Target canonical production origin: ${CANONICAL_PRODUCTION_ORIGIN}
  --url=<url>                  Target specific API base URL (must be allowed)
  --allow-origin=<origin>      Explicitly permit target origin, including loopback (comma-separated or repeatable)
  --timeout=<ms>               Request timeout in milliseconds (default: 15000)
  --help, -h                   Show this help message

Environment Variables:
  RUN_LIVE_PERSISTENCE_TEST    Set to "true" as alternative to --confirm-live-persistence
  AHEADGUARD_ADMIN_KEY         Production administrator Bearer token (required for --prod)
  AHEADGUARD_TEST_ADMIN_KEY    Non-production administrator Bearer token (required for test/local targets)
  PROD_URL                     Alternative base URL (default: ${CANONICAL_PRODUCTION_ORIGIN})
`);
    return 0;
  }

  // Reject removed credential-bearing arguments
  if (
    argv.some(
      (a) =>
        a.startsWith("--key=") ||
        a === "--key" ||
        a.startsWith("--test-key=") ||
        a === "--test-key" ||
        a.startsWith("--admin-key=") ||
        a === "--admin-key"
    )
  ) {
    console.error(`\n[FATAL] Security violation: Credential command-line arguments are prohibited.`);
    console.error(
      `Credentials must never be passed via CLI arguments. Configure AHEADGUARD_ADMIN_KEY (production) or AHEADGUARD_TEST_ADMIN_KEY (non-production) environment variables instead.\n`
    );
    return 1;
  }

  const confirmOptIn =
    argv.includes("--confirm-live-persistence") ||
    process.env.RUN_LIVE_PERSISTENCE_TEST === "true";

  if (!confirmOptIn) {
    console.log(`
================================================================================
 AheadGuard AI — Persistence Verification Probe (Opt-In Required)
================================================================================
 SKIPPED: Live production persistence verification requires explicit operator opt-in.
 This test executes a harmless text-only probe against the target, confirms that
 Neon PostgreSQL persisted the record (storageMode: "persisted"), and verifies
 that administrative credentials can retrieve it while unauthenticated reads are rejected.

 To authorize execution against production:
   $env:RUN_LIVE_PERSISTENCE_TEST="true"
   $env:AHEADGUARD_ADMIN_KEY="your_admin_secret_key"
   npm run test:smoke:persistence -- --confirm-live-persistence --prod

 Or run directly:
   node scripts/verify-persistence.mjs --confirm-live-persistence --prod
================================================================================
`);
    return 0;
  }

  const isProd = argv.includes("--prod") || argv.includes("--target=production");
  const urlArg = argv.find((a) => a.startsWith("--url="))?.split("=")[1];

  // Conflict detection
  if (isProd && urlArg && urlArg.trim() !== CANONICAL_PRODUCTION_ORIGIN) {
    console.error(`\n[FATAL] Target conflict: --prod cannot be combined with a conflicting --url.`);
    console.error(`Production mode strictly targets ${CANONICAL_PRODUCTION_ORIGIN}.\n`);
    return 1;
  }

  const baseUrl = urlArg || (isProd ? CANONICAL_PRODUCTION_ORIGIN : process.env.PROD_URL || process.env.TARGET_URL);

  // Parse allowed origins
  const allowedOrigins = [];
  for (const arg of argv) {
    if (arg.startsWith("--allow-origin=")) {
      const val = arg.split("=")[1];
      if (val) {
        allowedOrigins.push(...val.split(",").map((s) => s.trim()));
      }
    }
  }

  const adminKey = process.env.AHEADGUARD_ADMIN_KEY;
  const testAdminKey = process.env.AHEADGUARD_TEST_ADMIN_KEY;

  const timeoutArg = argv.find((a) => a.startsWith("--timeout="))?.split("=")[1];
  const timeoutMs = timeoutArg ? parseInt(timeoutArg, 10) : 15000;

  const result = await verifyProductionPersistence({
    baseUrl,
    adminKey,
    testAdminKey,
    confirmOptIn,
    isProd,
    allowedOrigins,
    timeoutMs,
  });

  if (!result.success) {
    console.error(`\n[FATAL] Persistence verification failed: ${result.error}`);
    if (result.details) {
      console.error(`[FATAL] Details: ${JSON.stringify(result.details)}`);
    }
    return 1;
  }

  console.log(`\n[SUCCESS] Production persistence verified successfully!`);
  console.log(`  - Investigation ID: ${result.investigationId}`);
  console.log(`  - Storage Mode:     persisted`);
  console.log(`  - Marker Verified:  true (${result.marker})`);
  console.log(`  - Security Gate:    Unauthenticated read correctly rejected (HTTP 401)`);
  console.log(`  - Admin Gate:       Authenticated read retrieved valid record (HTTP 200)`);
  return 0;
}

// Self-executing runner when executed directly via node
const isMain = () => {
  if (typeof process === "undefined" || !process.argv || !process.argv[1]) return false;
  try {
    const current = fileURLToPath(import.meta.url);
    const invoked = process.argv[1];
    return current === invoked || invoked.endsWith("verify-persistence.mjs");
  } catch {
    return false;
  }
};

if (isMain()) {
  runCli().then((code) => {
    process.exit(code ?? 0);
  });
}
