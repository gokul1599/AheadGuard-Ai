#!/usr/bin/env node

/**
 * AheadGuard AI — Production Persistence Verification Probe
 *
 * Dedicated opt-in verification script for end-to-end database persistence.
 *
 * Requirements enforced:
 * 1. Explicit operator opt-in required (RUN_LIVE_PERSISTENCE_TEST=true or --confirm-live-persistence).
 * 2. Deliberate target selection (--prod or explicit --url).
 * 3. Harmless text-only payload containing NO URLs (ensures zero TinyFish provider charges).
 * 4. Unique, searchable marker in payload for audit trail verification.
 * 5. Requires POST response to confirm report.investigationId, report.persisted === true, and report.storageMode === "persisted".
 * 6. Security check: Verifies unauthenticated GET /api/investigate?id=<id> returns HTTP 401 Unauthorized.
 * 7. Authorized retrieval: Verifies GET /api/investigate?id=<id> with Authorization: Bearer <key> returns HTTP 200 with matching ID.
 * 8. Never leaks secrets, tokens, connection strings, or headers in errors or logs.
 * 9. Does NOT invent record deletion endpoints (ledger immutability preserved).
 * 10. Bounded request timeouts with safe error redaction.
 */

import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

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
 * Redacts known and heuristic secrets from text, error messages, and log strings.
 */
export function sanitizeSecrets(text, secrets = []) {
  if (!text || typeof text !== "string") {
    return "";
  }
  let sanitized = text;

  // Redact explicit secrets passed in
  for (const secret of secrets) {
    if (secret && typeof secret === "string" && secret.trim().length > 0) {
      sanitized = sanitized.replaceAll(secret, "[REDACTED]");
    }
  }

  // Redact Bearer tokens, PostgreSQL connection URLs, and common secret keys
  sanitized = sanitized
    .replace(/Bearer\s+[a-zA-Z0-9_\-.~+/]+=*/gi, "Bearer [REDACTED]")
    .replace(/postgres(?:ql)?:\/\/[^\s"']+/gi, "postgres://[REDACTED]")
    .replace(/(?:tf_|api[-_]?key|key|secret|token|password)[=:\s]+[A-Za-z0-9_\-.]{8,}/gi, "$1=[REDACTED]")
    .replace(/\bat\s+.*?(?:\.ts|\.js|\.mjs|\.cjs)(?::\d+:\d+)?/gi, "")
    .trim();

  return sanitized;
}

/**
 * Safely parses a response body as JSON with error containment and secret redaction.
 */
export async function safeParseJsonResponse(response, stepName, secrets = []) {
  let rawText = "";
  try {
    rawText = await response.text();
  } catch (err) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    throw new Error(
      sanitizeSecrets(`Failed to read response body during ${stepName}: ${rawMsg}`, secrets)
    );
  }

  try {
    return JSON.parse(rawText);
  } catch {
    const snippet = rawText.length > 120 ? `${rawText.substring(0, 120)}...` : rawText;
    throw new Error(
      sanitizeSecrets(
        `${stepName} returned invalid non-JSON payload (HTTP ${response.status}): ${snippet}`,
        secrets
      )
    );
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
 */

/**
 * Core persistence verification engine.
 *
 * @param {Object} [options]
 * @param {string} [options.baseUrl] - Target API base URL (e.g. "https://aheadguard-ai.vercel.app")
 * @param {string} [options.adminKey] - Admin key for Authorization: Bearer <key>
 * @param {boolean} [options.confirmOptIn] - Explicit operator authorization flag
 * @param {number} [options.timeoutMs] - Request timeout in milliseconds (default: 15000)
 * @param {Function} [options.fetchFn] - Optional fetch implementation (for unit testing)
 * @param {Object} [options.logger] - Optional logger interface
 * @returns {Promise<PersistenceVerificationResult>} Verification result
 */
export async function verifyProductionPersistence(options = {}) {
  const {
    baseUrl: rawBaseUrl,
    adminKey: rawAdminKey,
    confirmOptIn = false,
    timeoutMs = 15000,
    fetchFn = globalThis.fetch,
    logger,
  } = options;

  const log = (msg) => logger?.log ? logger.log(msg) : console.log(msg);
  const warn = (msg) => logger?.warn ? logger.warn(msg) : console.warn(msg);

  // 1. Enforce explicit operator opt-in gate (Zero requests made if unconfirmed)
  if (!confirmOptIn) {
    return {
      success: false,
      optedIn: false,
      error:
        "Opt-in required: Live production persistence verification makes real HTTP requests and creates a verified record in Neon PostgreSQL. Pass --confirm-live-persistence or set RUN_LIVE_PERSISTENCE_TEST=true to authorize execution.",
    };
  }

  // 2. Validate target URL
  const trimmedUrl = (rawBaseUrl || "").trim();
  if (!trimmedUrl) {
    return {
      success: false,
      optedIn: true,
      error:
        "Target URL required. Specify --prod to target https://aheadguard-ai.vercel.app or provide --url=https://...",
    };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(trimmedUrl);
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      throw new Error("Protocol must be http: or https:");
    }
  } catch (urlErr) {
    const rawMsg = urlErr instanceof Error ? urlErr.message : String(urlErr);
    return {
      success: false,
      optedIn: true,
      error: `Invalid target URL: "${trimmedUrl}" (${rawMsg})`,
    };
  }

  const baseUrl = parsedUrl.origin;

  // 3. Validate Administrator Key
  const adminKey = (rawAdminKey || "").trim();
  if (!adminKey) {
    return {
      success: false,
      optedIn: true,
      error:
        "AHEADGUARD_ADMIN_KEY is required to retrieve the persisted record and verify administrative access.",
    };
  }

  // Secrets list for output/error redaction
  const secrets = [adminKey];
  if (process.env.DATABASE_URL) secrets.push(process.env.DATABASE_URL);
  if (process.env.TINYFISH_API_KEY) secrets.push(process.env.TINYFISH_API_KEY);

  const marker = generatePersistenceMarker();
  const payload = buildHarmlessPersistencePayload(marker);

  log(`[AheadGuard Persistence Verifier] Starting verification against ${baseUrl}`);
  log(`[AheadGuard Persistence Verifier] Marker: ${marker}`);

  // Helper for bounded fetch
  const executeBoundedFetch = async (url, fetchOptions, stepName) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetchFn(url, {
        ...fetchOptions,
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new Error(
          sanitizeSecrets(`Request timed out after ${timeoutMs}ms during ${stepName} (${url})`, secrets)
        );
      }
      const rawMsg = err instanceof Error ? err.message : String(err);
      throw new Error(
        sanitizeSecrets(`Network failure during ${stepName}: ${rawMsg}`, secrets)
      );
    } finally {
      clearTimeout(timer);
    }
  };

  let investigationId;

  // =========================================================================
  // STEP 1: POST harmless text-only probe to create a persisted record
  // =========================================================================
  try {
    const postRes = await executeBoundedFetch(
      `${baseUrl}/api/investigate`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: JSON.stringify(payload),
      },
      "POST harmless text-only investigation"
    );

    if (!postRes.ok) {
      const errorData = await safeParseJsonResponse(postRes, "POST investigation error check", secrets).catch(() => ({}));
      const errDetail = errorData?.error ? `: ${errorData.error}` : "";
      return {
        success: false,
        optedIn: true,
        marker,
        error: sanitizeSecrets(`POST /api/investigate failed with HTTP ${postRes.status}${errDetail}`, secrets),
        details: { postStatus: postRes.status },
      };
    }

    const postData = await safeParseJsonResponse(postRes, "POST investigation", secrets);
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
        error: `POST /api/investigate returned invalid investigationId: "${String(investigationId)}"`,
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
    const unauthRes = await executeBoundedFetch(
      `${baseUrl}/api/investigate?id=${encodeURIComponent(investigationId)}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
        },
      },
      "Unauthenticated record retrieval check"
    );

    unauthStatus = unauthRes.status;
    if (unauthStatus !== 401) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error: sanitizeSecrets(
          `Security check failed: unauthenticated read of investigation '${investigationId}' returned HTTP ${unauthStatus}, expected HTTP 401 Unauthorized.`,
          secrets
        ),
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
    const authRes = await executeBoundedFetch(
      `${baseUrl}/api/investigate?id=${encodeURIComponent(investigationId)}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Authorization": `Bearer ${adminKey}`,
        },
      },
      "Authenticated record retrieval"
    );

    authStatus = authRes.status;

    if (authStatus === 401) {
      return {
        success: false,
        optedIn: true,
        investigationId,
        marker,
        error:
          "Admin authentication failed: server rejected the provided AHEADGUARD_ADMIN_KEY with HTTP 401 Unauthorized.",
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
        error: `Persisted record '${investigationId}' was not found in the database (HTTP 404). The write may not have committed.`,
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
        error: sanitizeSecrets(`Authenticated record read failed with HTTP ${authStatus}`, secrets),
        details: {
          postStatus: 200,
          unauthGetStatus: 401,
          authGetStatus: authStatus,
          storageMode: "persisted",
          persisted: true,
        },
      };
    }

    const authData = await safeParseJsonResponse(authRes, "Authenticated record read", secrets);
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
        error: `Retrieved record ID '${retrievedReport.investigationId}' does not match expected ID '${investigationId}'.`,
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

    log(`[AheadGuard Persistence Verifier] Authenticated read succeeded: ID=${retrievedReport.investigationId}, outcome="${retrievedReport.riskOutcome}"`);
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
  --prod                       Target production https://aheadguard-ai.vercel.app
  --url=<url>                  Target specific API base URL
  --key=<key>                  Administrator key (defaults to AHEADGUARD_ADMIN_KEY env var)
  --timeout=<ms>               Request timeout in milliseconds (default: 15000)
  --help, -h                   Show this help message

Environment Variables:
  RUN_LIVE_PERSISTENCE_TEST    Set to "true" as alternative to --confirm-live-persistence
  AHEADGUARD_ADMIN_KEY         Administrator Bearer token for record retrieval
  PROD_URL                     Alternative base URL (default: https://aheadguard-ai.vercel.app)
`);
    return 0;
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
  const baseUrl = urlArg || (isProd ? "https://aheadguard-ai.vercel.app" : process.env.PROD_URL || process.env.TARGET_URL);

  const keyArg = argv.find((a) => a.startsWith("--key="))?.split("=")[1];
  const adminKey = keyArg || process.env.AHEADGUARD_ADMIN_KEY;

  const timeoutArg = argv.find((a) => a.startsWith("--timeout="))?.split("=")[1];
  const timeoutMs = timeoutArg ? parseInt(timeoutArg, 10) : 15000;

  const result = await verifyProductionPersistence({
    baseUrl,
    adminKey,
    confirmOptIn,
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
