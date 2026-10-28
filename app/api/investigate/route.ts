import { NextResponse } from "next/server";
import { InputSchema } from "@/lib/types";
import { validateAndNormalizeUrl } from "@/lib/url-safety";
import { sanitizeUrlForSharing } from "@/lib/share-report";
import { executeTinyFishInvestigation } from "@/lib/tinyfish";
import { assessInvestigation } from "@/lib/policy";
import { analyzeMessageText } from "@/lib/message-intelligence";
import { verifyCompanyIdentity, verifyJobListing } from "@/lib/company-verification";
import { enrichReportWithScamIntelligence, createTextOnlyReport } from "@/lib/claims-evaluator";
import { saveInvestigation, getRecentInvestigations, getInvestigationById, testDatabaseConnection } from "@/lib/db";
import type { ProgressEvent, InvestigationReport } from "@/lib/types";
import {
  isAllowedOrigin,
  checkRateLimit,
  getClientIp,
  verifyAdminAuth,
} from "@/lib/api-security";

export const runtime = "nodejs";
export const maxDuration = 120;

function getCorsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  if (origin && isAllowedOrigin(origin)) {
    return {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept",
      "Vary": "Origin",
    };
  }
  return {
    "Vary": "Origin",
  };
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin || !isAllowedOrigin(origin)) {
    return new Response("CORS origin not allowed.", { status: 403 });
  }
  const headers = getCorsHeaders(request);
  return new Response(null, {
    status: 204,
    headers: {
      ...headers,
      "Access-Control-Max-Age": "86400",
    },
  });
}

function jsonResponse(request: Request, data: unknown, init?: { status?: number; headers?: Record<string, string> }) {
  const cors = getCorsHeaders(request);
  return NextResponse.json(data, {
    status: init?.status ?? 200,
    headers: {
      ...cors,
      ...(init?.headers ?? {}),
    },
  });
}

function sanitizeClientError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error || "Unexpected investigation error.");
  // Redact any potential API keys, secrets, tokens, or local stack paths
  return raw
    .replace(/(?:tf_|api[-_]?key|key|secret|token|bearer)[=:\s]+[A-Za-z0-9_\-\.]{8,}/gi, "[REDACTED]")
    .replace(/\bat\s+.*?(?:\.ts|\.js|\.mjs|\.cjs)(?::\d+:\d+)?/gi, "")
    .replace(/[A-Za-z]:\\[^\s]+/g, "")
    .replace(/\/[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+/g, "")
    .trim() || "An unexpected investigation error occurred.";
}

export async function GET(request: Request) {
  const origin = request.headers.get("origin");
  if (origin && !isAllowedOrigin(origin)) {
    return new Response("CORS origin not allowed.", { status: 403 });
  }

  // Rate limiting & abuse protection
  const clientIp = getClientIp(request);
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    return jsonResponse(
      request,
      { error: "Too many requests. Please wait." },
      {
        status: 429,
        headers: {
          "Retry-After": String(rateLimit.retryAfter || 60),
          "X-RateLimit-Limit": String(rateLimit.limit),
          "X-RateLimit-Remaining": "0",
        },
      }
    );
  }

  const { searchParams } = new URL(request.url);
  const action = searchParams.get("action");
  const id = searchParams.get("id");

  // Protected Record Access: Querying individual investigations or centralized history requires Admin authorization
  if (id || action === "history") {
    if (!verifyAdminAuth(request)) {
      return jsonResponse(
        request,
        { error: "Unauthorized: administrator credentials required to access stored records." },
        { status: 401 }
      );
    }

    if (id) {
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
        return jsonResponse(request, { error: "Invalid investigation ID format." }, { status: 400 });
      }
      const report = await getInvestigationById(id);
      if (!report) {
        return jsonResponse(request, { error: "Investigation report not found." }, { status: 404 });
      }
      return jsonResponse(request, { report }, { status: 200 });
    }

    if (action === "history") {
      const history = await getRecentInvestigations(20);
      return jsonResponse(request, { investigations: history }, { status: 200 });
    }
  }

  // Safe database health check: returns connection status without leaking schema, version, or credentials
  const dbStatus = await testDatabaseConnection();
  const statusCode = dbStatus.ok ? 200 : dbStatus.status === "unconfigured" ? 200 : 503;
  return jsonResponse(request, { db: dbStatus }, { status: statusCode });
}

export async function POST(request: Request) {
  const origin = request.headers.get("origin");
  if (origin && !isAllowedOrigin(origin)) {
    return new Response("CORS origin not allowed.", { status: 403 });
  }

  // Defensively reject oversized payloads (max 16KB for URL / message investigation request)
  const contentLength = request.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > 16384) {
    return jsonResponse(request, { error: "Payload too large (max 16KB)." }, { status: 413 });
  }

  // Rate limiting & public abuse protection
  const clientIp = getClientIp(request);
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    return jsonResponse(
      request,
      { error: "Too many investigation requests. Please wait before submitting another destination." },
      {
        status: 429,
        headers: {
          "Retry-After": String(rateLimit.retryAfter || 60),
          "X-RateLimit-Limit": String(rateLimit.limit),
          "X-RateLimit-Remaining": "0",
        },
      }
    );
  }

  try {
    // 1. Parse and validate body
    let rawJson: unknown;
    try {
      rawJson = await request.json();
    } catch {
      return jsonResponse(request, { error: "Invalid JSON request body." }, { status: 400 });
    }

    const parseResult = InputSchema.safeParse(rawJson);
    if (!parseResult.success) {
      const issue = parseResult.error.issues[0];
      return jsonResponse(request, { error: issue?.message || "Invalid input." }, { status: 400 });
    }

    const {
      input,
      messageText,
      targetUrl: explicitTargetUrl,
      claimedOrganization,
      claimedJobRole,
      officialCareersUrl,
      analysisMode,
    } = parseResult.data;

    // 2. Perform Message Intelligence & Claim Extraction
    const rawMessage = (messageText || input).trim();
    const isExplicitLinkMode = analysisMode === "link";

    const messageData = analyzeMessageText({
      rawMessage,
      userSpecifiedOrg: claimedOrganization,
      userSpecifiedRole: claimedJobRole,
      targetUrl: explicitTargetUrl,
    });

    const acceptsSse = request.headers.get("accept")?.includes("text/event-stream");

    // 3. Resolve destination URL to investigate
    let candidateUrl = explicitTargetUrl?.trim();

    if (!candidateUrl) {
      if (isExplicitLinkMode) {
        candidateUrl = input.trim();
      } else if (messageData.extractedUrls.length === 1) {
        candidateUrl = messageData.extractedUrls[0];
      } else if (messageData.extractedUrls.length > 1) {
        // Multiple URLs detected in message -> Classify each against security & privacy policy
        const classified = messageData.extractedUrls.map((rawUrl) => {
          const val = validateAndNormalizeUrl(rawUrl);
          return {
            rawUrl,
            sanitizedUrl: sanitizeUrlForSharing(rawUrl),
            isSafe: val.valid,
            error: val.valid ? undefined : val.error,
          };
        });

        const safeUrls = classified.filter((c) => c.isSafe).map((c) => c.rawUrl);
        const rejectedUrls = classified.filter((c) => !c.isSafe);

        // Fail-closed: If every extracted link contains sensitive credentials or is unsafe, reject pre-flight
        if (safeUrls.length === 0) {
          return jsonResponse(
            request,
            {
              error:
                "All extracted destination URLs contain sensitive authentication tokens or credentials and cannot be investigated to protect your privacy and security. Please remove credentials before submitting.",
            },
            { status: 400 }
          );
        }

        // Clean messageData to guarantee NO raw secrets appear in client responses
        const safeMessageData = {
          ...messageData,
          originalText: messageData.redactedText,
          extractedUrls: safeUrls,
          singleExtractedUrl: safeUrls.length === 1 ? safeUrls[0] : undefined,
        };

        const rejectedNote =
          rejectedUrls.length > 0
            ? ` (${rejectedUrls.length} link containing sensitive credentials or unsafe destination was omitted for privacy).`
            : "";

        const promptMessage = `Multiple destination links detected in message. Please select which destination to investigate.${rejectedNote}`;

        if (acceptsSse) {
          return new Response(
            `event: multiple_urls\ndata: ${JSON.stringify({
              type: "multiple_urls",
              extractedUrls: safeUrls,
              message: promptMessage,
              messageData: safeMessageData,
            })}\n\n`,
            {
              headers: {
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-cache, no-transform",
                Connection: "keep-alive",
                ...getCorsHeaders(request),
              },
            }
          );
        } else {
          return jsonResponse(
            request,
            {
              multipleUrls: true,
              extractedUrls: safeUrls,
              message: promptMessage,
              messageData: safeMessageData,
            },
            { status: 200 }
          );
        }
      } else {
        // 0 URLs extracted. Test if input itself is a valid URL
        const directCheck = validateAndNormalizeUrl(input.trim());
        if (directCheck.valid) {
          candidateUrl = directCheck.normalizedUrl;
        }
      }
    }

    // 4. Handle Text-Only Message Analysis (no URL present)
    if (!candidateUrl) {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: messageData.claimedOrganization,
        userProvidedCareersUrl: officialCareersUrl,
      });

      const jobVerification = verifyJobListing({
        claimedRole: messageData.claimedJobRole,
        claimedEmployer: messageData.claimedOrganization || companyIdentity.claimedOrganization,
        companyIdentity,
        feeWarningPresent: Boolean(messageData.recruitmentFeeWarning?.detected),
      });

      const safeMessageData = {
        ...messageData,
        originalText: messageData.redactedText,
        extractedUrls: messageData.extractedUrls.map(sanitizeUrlForSharing),
      };

      const textReport = createTextOnlyReport({
        messageData: safeMessageData,
        companyIdentity,
        jobVerification,
      });

      // Persist to Neon (non-blocking failure, strictly bounded to max 5s)
      try {
        const dbRes = await saveInvestigation(textReport);
        textReport.persisted = dbRes.ok;
        textReport.storageMode = dbRes.ok ? "persisted" : "ephemeral";
        if (!dbRes.ok && dbRes.error !== "Database not configured") {
          console.warn("[DB] Non-fatal text report persistence warning:", dbRes.error);
        }
      } catch (dbErr) {
        textReport.persisted = false;
        textReport.storageMode = "ephemeral";
        console.error("[DB] Non-fatal text report persistence error:", dbErr instanceof Error ? dbErr.message : String(dbErr));
      }

      if (acceptsSse) {
        return new Response(
          `event: report\ndata: ${JSON.stringify({ type: "report", report: textReport })}\n\n`,
          {
            headers: {
              "Content-Type": "text/event-stream; charset=utf-8",
              "Cache-Control": "no-cache, no-transform",
              Connection: "keep-alive",
              ...getCorsHeaders(request),
            },
          }
        );
      } else {
        return jsonResponse(request, { report: textReport }, { status: 200 });
      }
    }

    // 5. Validate destination URL and verify network safety
    const validation = validateAndNormalizeUrl(candidateUrl);
    if (!validation.valid) {
      return jsonResponse(request, { error: validation.error }, { status: 400 });
    }

    // 6. Verify server-side TinyFish API key
    const apiKey = process.env.TINYFISH_API_KEY;
    if (!apiKey || apiKey.trim().length === 0) {
      return jsonResponse(
        request,
        {
          error: "TinyFish is not configured yet. Add TINYFISH_API_KEY to .env.local, then restart your server.",
        },
        { status: 503 }
      );
    }

    // Helper to synthesize final scam & identity intelligence
    const finalizeReport = (baseReport: InvestigationReport): InvestigationReport => {
      const companyIdentity = verifyCompanyIdentity({
        claimedOrg: messageData.claimedOrganization || baseReport.claimedOrganization,
        destinationUrl: validation.normalizedUrl,
        userProvidedCareersUrl: officialCareersUrl,
      });

      const jobVerification = verifyJobListing({
        claimedRole: messageData.claimedJobRole,
        claimedEmployer: messageData.claimedOrganization || companyIdentity.claimedOrganization,
        jobListingUrl: validation.normalizedUrl,
        companyIdentity,
        feeWarningPresent: Boolean(messageData.recruitmentFeeWarning?.detected),
        observedPageTitle: baseReport.observedFacts?.pageTitle,
        observedPageSnippet: baseReport.observedFacts?.visiblePurpose,
      });

      const safeMessageData = {
        ...messageData,
        originalText: messageData.redactedText,
        extractedUrls: messageData.extractedUrls.map(sanitizeUrlForSharing),
      };

      return enrichReportWithScamIntelligence({
        report: baseReport,
        messageData: safeMessageData,
        companyIdentity,
        jobVerification,
        analysisMode: analysisMode || (isExplicitLinkMode ? "link" : "message"),
      });
    };

    // 7. Handle Real-Time SSE Streaming to Client
    if (acceptsSse) {
      const encoder = new TextEncoder();
      const stream = new TransformStream();
      const writer = stream.writable.getWriter();

      let writeChain = Promise.resolve();
      const sendEvent = (event: ProgressEvent | { type: "report"; report: unknown }): Promise<void> => {
        writeChain = writeChain.then(async () => {
          try {
            const payload = `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
            await writer.write(encoder.encode(payload));
          } catch {
            // Client might have disconnected
          }
        });
        return writeChain;
      };

      // Execute investigation asynchronously while streaming events
      (async () => {
        try {
          await sendEvent({
            type: "started",
            message: "Validation passed. Initiating TinyFish read-only investigation…",
            timestamp: new Date().toISOString(),
          });

          const tinyFishResult = await executeTinyFishInvestigation({
            url: validation.normalizedUrl,
            apiKey,
            onProgress: (progress) => {
              void sendEvent(progress);
            },
          });

          const baseReport = assessInvestigation({
            submittedUrl: validation.url,
            tinyFishResult,
          });

          const finalReport = finalizeReport(baseReport);

          // 1. Await Neon persistence before sending the final report to guarantee accurate persistence status
          // Keeping writer open guarantees the serverless context remains active until the write completes or safely times out
          let dbRes: { ok: boolean; error?: string } = { ok: false, error: "Database not configured" };
          try {
            dbRes = await saveInvestigation(finalReport);
            if (!dbRes.ok && dbRes.error !== "Database not configured") {
              console.warn("[DB] Non-fatal streaming report persistence warning:", dbRes.error);
            }
          } catch (dbErr) {
            console.error("[DB] Non-fatal streaming report persistence error:", dbErr instanceof Error ? dbErr.message : String(dbErr));
          }
          finalReport.persisted = dbRes.ok;
          finalReport.storageMode = finalReport.isDemo ? "demo" : dbRes.ok ? "persisted" : "ephemeral";

          // 2. Stream final report event with accurate persistence metadata
          await sendEvent({
            type: "report",
            report: finalReport,
          });
        } catch (error) {
          const message = sanitizeClientError(error);
          const isTimeout = /timed out|timeout/i.test(message);

          const failureReport = assessInvestigation({
            submittedUrl: validation.url,
            tinyFishResult: {
              success: false,
              goalFailed: true,
              errorMessage: isTimeout ? "Investigation timed out after 110s." : message,
              eventsCount: 0,
              rawAgentText: "",
            },
          });

          const finalizedFailureReport = finalizeReport(failureReport);

          await sendEvent({
            type: "error",
            message: isTimeout ? "Investigation timed out. No safe verdict was issued." : message,
            timestamp: new Date().toISOString(),
            error: message,
            report: finalizedFailureReport,
          });
        } finally {
          await writeChain;
          await writer.close().catch(() => undefined);
        }
      })();

      return new Response(stream.readable, {
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          "X-Accel-Buffering": "no",
          ...getCorsHeaders(request),
        },
      });
    }

    // 8. Standard JSON endpoint for non-streaming clients
    try {
      const tinyFishResult = await executeTinyFishInvestigation({
        url: validation.normalizedUrl,
        apiKey,
      });

      const baseReport = assessInvestigation({
        submittedUrl: validation.url,
        tinyFishResult,
      });

      const finalReport = finalizeReport(baseReport);

      // Persist to Neon before returning response (bounded by 5s withTimeout)
      let dbRes: { ok: boolean; error?: string } = { ok: false, error: "Database not configured" };
      try {
        dbRes = await saveInvestigation(finalReport);
        if (!dbRes.ok && dbRes.error !== "Database not configured") {
          console.warn("[DB] Non-fatal JSON report persistence warning:", dbRes.error);
        }
      } catch (dbErr) {
        console.error("[DB] Non-fatal JSON report persistence error:", dbErr instanceof Error ? dbErr.message : String(dbErr));
      }
      finalReport.persisted = dbRes.ok;
      finalReport.storageMode = finalReport.isDemo ? "demo" : dbRes.ok ? "persisted" : "ephemeral";

      return jsonResponse(request, { report: finalReport }, { status: 200 });
    } catch (error) {
      const message = sanitizeClientError(error);
      const isTimeout = /timed out|timeout/i.test(message);

      const failureReport = assessInvestigation({
        submittedUrl: validation.url,
        tinyFishResult: {
          success: false,
          goalFailed: true,
          errorMessage: isTimeout ? "Investigation timed out after 110s." : message,
          eventsCount: 0,
          rawAgentText: "",
        },
      });

      const finalizedFailureReport = finalizeReport(failureReport);

      return jsonResponse(
        request,
        {
          error: isTimeout ? "The investigation timed out. No safe verdict was issued." : message,
          report: finalizedFailureReport,
        },
        { status: isTimeout ? 504 : 502 }
      );
    }
  } catch (error) {
    const message = sanitizeClientError(error);
    return jsonResponse(request, { error: message }, { status: 500 });
  }
}
