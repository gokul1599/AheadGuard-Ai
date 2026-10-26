import type { InvestigationReport, RiskOutcome } from "./types";
import { validateAndNormalizeUrl } from "../../lib/url-safety";

export interface CheckOptions {
  url: string;
  backendUrl?: string;
  onProgress?: (message: string) => void;
  signal?: AbortSignal;
}

const DEFAULT_BACKEND_URL = "http://localhost:3000";

/**
 * Sanitizes errors to prevent exposing internal stack frames or tokens.
 */
function sanitizeClientMessage(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error || "Investigation service unavailable");
  return text
    .replace(/(?:tf_|api[-_]?key|key|secret|token|bearer)[=:\s]+[A-Za-z0-9_\-\.]{8,}/gi, "[REDACTED]")
    .replace(/\bat\s+.*?(?:\.ts|\.js|\.mjs|\.cjs)(?::\d+:\d+)?/gi, "")
    .replace(/[A-Za-z]:\\[^\s]+/g, "")
    .replace(/\/[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+/g, "")
    .trim() || "An unexpected investigation error occurred.";
}

/**
 * Creates a fallback Unknown report when an error or timeout occurs.
 */
export function createUnknownReport(targetUrl: string, reason: string): InvestigationReport {
  let host = "destination";
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    // Keep fallback host
  }

  return {
    investigationId: `inv_err_${Date.now()}`,
    timestamp: new Date().toISOString(),
    originalUrl: targetUrl,
    normalizedUrl: targetUrl,
    observedDestination: {
      submittedUrl: targetUrl,
      normalizedUrl: targetUrl,
      submittedHost: host,
      destinationChanged: false,
      redirectChain: [targetUrl],
    },
    checksPerformed: [
      {
        name: "Backend Connection",
        status: "failed",
        detail: reason,
      },
    ],
    evidenceItems: [
      {
        label: "Investigation Inconclusive",
        detail: reason,
        kind: "neutral",
        provenance: "policy_rule",
      },
    ],
    observedFacts: {
      credentialOrPaymentRequest: false,
      downloadOrPermissionRequest: false,
      formsObserved: false,
      hasPasswordField: false,
      hasPaymentField: false,
      hasPunycode: host.includes("xn--"),
      isNumericIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(host),
      isHttp: targetUrl.startsWith("http:"),
    },
    modelInterpretations: [],
    warningSigns: [],
    missingEvidence: ["Live remote browser inspection could not complete"],
    actionPreview: {
      proposedAction: `Navigating to ${host}.`,
      consequenceIfProceed:
        "The destination could not be validated by AheadGuard. Proceed with extra caution and do not enter personal or financial information.",
      riskFactors: ["Destination status is unverified."],
    },
    riskOutcome: "Unknown" as RiskOutcome,
    threatLikelihood: "Uncertain",
    consequenceImpact: "Moderate",
    outcomeReason: `Investigation incomplete: ${reason}. Inconclusive results cannot be treated as safe.`,
    recommendedAction: "Verify the destination through an independently confirmed channel before proceeding.",
    limitations: [
      "AheadGuard could not reach or complete the live investigation with the local backend.",
      "Absence of threat indicators is not proof of safety.",
    ],
    eventsCount: 0,
  };
}

/**
 * Executes destination investigation by connecting to AheadGuard backend.
 */
export async function investigateUrl(options: CheckOptions): Promise<InvestigationReport> {
  const { url, backendUrl = DEFAULT_BACKEND_URL, onProgress, signal } = options;

  // 1. Client-side URL & Network Safety check
  const validation = validateAndNormalizeUrl(url);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  const endpoint = `${backendUrl.replace(/\/+$/, "")}/api/investigate`;
  const timeoutSignal = AbortSignal.timeout(115_000);
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

  onProgress?.("Connecting to AheadGuard backend…");

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream, application/json",
      },
      body: JSON.stringify({ input: validation.normalizedUrl }),
      signal: combinedSignal,
    });

    const contentType = response.headers.get("content-type") || "";

    // 2. Handle Real-Time SSE response
    if (contentType.includes("text/event-stream") && response.body) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let finalReport: InvestigationReport | undefined;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        let splitIdx: number;

        while ((splitIdx = buffer.search(/\r?\n\r?\n/)) >= 0) {
          const chunk = buffer.slice(0, splitIdx);
          const delimiter = buffer.slice(splitIdx).match(/^\r?\n\r?\n/)?.[0] ?? "\n\n";
          buffer = buffer.slice(splitIdx + delimiter.length);

          let eventType = "message";
          const dataLines: string[] = [];

          for (const line of chunk.split(/\r?\n/)) {
            if (line.startsWith("event:")) eventType = line.slice(6).trim();
            if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
          }

          if (!dataLines.length) continue;
          const dataText = dataLines.join("\n");

          try {
            const parsed = JSON.parse(dataText);
            if (eventType === "started" || eventType === "progress") {
              onProgress?.(parsed.message || "Investigating page…");
            } else if (eventType === "streaming_url") {
              onProgress?.("Remote browser session live…");
            } else if (eventType === "complete") {
              onProgress?.("Evaluating returned evidence…");
            } else if (eventType === "report") {
              finalReport = (parsed.report || parsed) as InvestigationReport;
            } else if (eventType === "error") {
              if (parsed.report) return parsed.report as InvestigationReport;
              throw new Error(parsed.error || parsed.message || "Investigation failed.");
            }
          } catch (jsonErr) {
            if (jsonErr instanceof Error && jsonErr.message !== "Unexpected token") {
              throw jsonErr;
            }
          }
        }
      }

      if (finalReport) return finalReport;
      throw new Error("Stream closed before receiving an investigation report.");
    }

    // 3. Handle JSON response
    const data = await response.json().catch(() => {
      throw new Error(`Failed to parse backend response (HTTP ${response.status}).`);
    });

    if (!response.ok) {
      if (data.report) return data.report as InvestigationReport;
      throw new Error(data.error || `Backend returned HTTP ${response.status}.`);
    }

    if (data.report) {
      return data.report as InvestigationReport;
    }

    throw new Error("Backend response did not contain an investigation report.");
  } catch (error) {
    const isTimeout = combinedSignal.aborted;
    const cleanMsg = isTimeout
      ? "Investigation timed out. The destination could not be validated."
      : sanitizeClientMessage(error);

    // Never return a fabricated safe report on failure; return a defensive Unknown report
    return createUnknownReport(validation.normalizedUrl, cleanMsg);
  }
}
