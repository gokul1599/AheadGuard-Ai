// lib/url-safety.ts
function extractUrlFromText(input) {
  if (!input || typeof input !== "string") return null;
  const candidate = input.match(/https?:\/\/[^\s<>"'`)]+/i)?.[0];
  if (!candidate) return null;
  return candidate.replace(/[),.;!?]+$/, "");
}
function isAlternateEncoding(part) {
  if (part.startsWith("0x") || part.startsWith("0X")) return true;
  if (part.length > 1 && part.startsWith("0") && /^\d+$/.test(part)) return true;
  return false;
}
function isPrivateOrReservedIpv4(a, b, c, d) {
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224 && a <= 239) return true;
  if (a >= 240) return true;
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  return false;
}
function isUnsafeDestination(hostname) {
  const host = hostname.toLowerCase().trim().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan") || host === "metadata.google.internal" || host === "instance-data") {
    return { unsafe: true, reason: "Local, internal, or cloud-metadata destinations cannot be investigated." };
  }
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") {
    return { unsafe: true, reason: "IPv6 loopback destination is not permitted." };
  }
  if (host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) {
    return { unsafe: true, reason: "IPv6 link-local and unique-local destinations are not permitted." };
  }
  if (host.startsWith("::ffff:") || host.startsWith("0:0:0:0:0:ffff:")) {
    const remainder = host.replace(/^(?:0:0:0:0:0:)?::?ffff:/, "");
    if (remainder.includes(".")) {
      const v4Check = isUnsafeDestination(remainder);
      if (v4Check.unsafe) return v4Check;
    }
    const hexWords = remainder.split(":");
    if (hexWords.length === 2) {
      const high = parseInt(hexWords[0], 16);
      const low = parseInt(hexWords[1], 16);
      if (!Number.isNaN(high) && !Number.isNaN(low)) {
        const a = high >> 8 & 255;
        const b = high & 255;
        const c = low >> 8 & 255;
        const d = low & 255;
        if (isPrivateOrReservedIpv4(a, b, c, d)) {
          return { unsafe: true, reason: "IPv4-mapped IPv6 destination maps to a private/reserved network." };
        }
      }
    }
  }
  if (/^\d{8,10}$/.test(host)) {
    const num = Number(host);
    if (!Number.isNaN(num) && num >= 0 && num <= 4294967295) {
      const a = num >>> 24 & 255;
      const b = num >>> 16 & 255;
      const c = num >>> 8 & 255;
      const d = num & 255;
      if (isPrivateOrReservedIpv4(a, b, c, d)) {
        return { unsafe: true, reason: "Dword integer IP destination maps to a private/reserved network." };
      }
    }
  }
  if (/^0x[0-9a-f]{1,8}$/i.test(host)) {
    const num = parseInt(host, 16);
    if (!Number.isNaN(num)) {
      const a = num >>> 24 & 255;
      const b = num >>> 16 & 255;
      const c = num >>> 8 & 255;
      const d = num & 255;
      if (isPrivateOrReservedIpv4(a, b, c, d)) {
        return { unsafe: true, reason: "Hexadecimal IP destination maps to a private/reserved network." };
      }
    }
  }
  const rawParts = host.split(".");
  if (rawParts.length === 4) {
    const hasAlternate = rawParts.some(isAlternateEncoding);
    if (hasAlternate) {
      const parsed = rawParts.map((p) => {
        if (p.startsWith("0x") || p.startsWith("0X")) return parseInt(p, 16);
        if (p.length > 1 && p.startsWith("0")) return parseInt(p, 8);
        return parseInt(p, 10);
      });
      if (parsed.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
        const [a, b, c, d] = parsed;
        if (isPrivateOrReservedIpv4(a, b, c, d)) {
          return { unsafe: true, reason: "Alternate encoded IP maps to a private or reserved network." };
        }
      }
    }
    const parts = rawParts.map(Number);
    if (parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      const [a, b, c, d] = parts;
      if (isPrivateOrReservedIpv4(a, b, c, d)) {
        return { unsafe: true, reason: "Private, local-loopback, or cloud-metadata IP destinations cannot be investigated." };
      }
    }
  }
  return { unsafe: false };
}
function validateAndNormalizeUrl(rawInput) {
  if (typeof rawInput === "string") {
    const trimmed = rawInput.trim();
    const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
    if (schemeMatch) {
      const scheme = schemeMatch[1].toLowerCase();
      if (scheme !== "http" && scheme !== "https") {
        return { valid: false, error: `Unsupported protocol (${scheme}:). Only HTTP and HTTPS destinations are supported.` };
      }
    }
  }
  const candidate = extractUrlFromText(rawInput);
  if (!candidate) {
    return { valid: false, error: "No http:// or https:// URL found. Please paste a valid URL or message containing one." };
  }
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: "The provided link is malformed or invalid." };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, error: `Unsupported protocol (${parsed.protocol}). Only HTTP and HTTPS destinations are supported.` };
  }
  if (parsed.username || parsed.password) {
    return { valid: false, error: "URLs containing embedded usernames or passwords are not permitted." };
  }
  const host = parsed.hostname;
  if (!host || host.length > 253) {
    return { valid: false, error: "The destination hostname is invalid or too long." };
  }
  if (parsed.port) {
    const portNum = Number(parsed.port);
    const allowedPorts = [80, 443, 8080, 8443, 3e3, 5e3];
    if (Number.isNaN(portNum) || portNum < 1 || portNum > 65535 || !allowedPorts.includes(portNum)) {
      return { valid: false, error: `Port ${parsed.port} is not supported. Use standard web ports (80, 443).` };
    }
  }
  const safetyCheck = isUnsafeDestination(host);
  if (safetyCheck.unsafe) {
    return { valid: false, error: safetyCheck.reason ?? "This destination cannot be investigated for security reasons." };
  }
  const hasPunycode = host.includes("xn--");
  const isNumericIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
  const isHttp = parsed.protocol === "http:";
  return {
    valid: true,
    url: parsed,
    normalizedUrl: parsed.toString(),
    hasPunycode,
    isNumericIp,
    isHttp
  };
}

// extension/src/config.ts
var PRODUCTION_BACKEND_URL = "https://aheadguard-ai.vercel.app";
var DEFAULT_BACKEND_URL = PRODUCTION_BACKEND_URL;
function isValidBackendEndpoint(url) {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return false;
    const host = parsed.hostname.toLowerCase();
    if (host === "aheadguard-ai.vercel.app") {
      return parsed.protocol === "https:" && (!parsed.port || parsed.port === "443");
    }
    if (host === "localhost" || host === "127.0.0.1") {
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    }
    return false;
  } catch {
    return false;
  }
}

// extension/src/api-client.ts
function sanitizeClientMessage(error) {
  const text = error instanceof Error ? error.message : String(error || "Investigation service unavailable");
  return text.replace(/(?:tf_|api[-_]?key|key|secret|token|bearer)[=:\s]+[A-Za-z0-9_\-\.]{8,}/gi, "[REDACTED]").replace(/\bat\s+.*?(?:\.ts|\.js|\.mjs|\.cjs)(?::\d+:\d+)?/gi, "").replace(/[A-Za-z]:\\[^\s]+/g, "").replace(/\/[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+/g, "").trim() || "An unexpected investigation error occurred.";
}
function createUnknownReport(targetUrl, reason) {
  let host = "destination";
  try {
    host = new URL(targetUrl).hostname;
  } catch {
  }
  return {
    investigationId: `inv_err_${Date.now()}`,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    originalUrl: targetUrl,
    normalizedUrl: targetUrl,
    observedDestination: {
      submittedUrl: targetUrl,
      normalizedUrl: targetUrl,
      submittedHost: host,
      destinationChanged: false,
      redirectChain: [targetUrl]
    },
    checksPerformed: [
      {
        name: "Backend Connection",
        status: "failed",
        detail: reason
      }
    ],
    evidenceItems: [
      {
        label: "Investigation Inconclusive",
        detail: reason,
        kind: "neutral",
        provenance: "policy_rule"
      }
    ],
    observedFacts: {
      credentialOrPaymentRequest: false,
      downloadOrPermissionRequest: false,
      formsObserved: false,
      hasPasswordField: false,
      hasPaymentField: false,
      hasPunycode: host.includes("xn--"),
      isNumericIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(host),
      isHttp: targetUrl.startsWith("http:")
    },
    modelInterpretations: [],
    warningSigns: [],
    missingEvidence: ["Live remote browser inspection could not complete"],
    actionPreview: {
      proposedAction: `Navigating to ${host}.`,
      consequenceIfProceed: "The destination could not be validated by AheadGuard. Proceed with extra caution and do not enter personal or financial information.",
      riskFactors: ["Destination status is unverified."]
    },
    riskOutcome: "Unknown",
    threatLikelihood: "Uncertain",
    consequenceImpact: "Moderate",
    outcomeReason: `Investigation incomplete: ${reason}. Inconclusive results cannot be treated as safe.`,
    recommendedAction: "Verify the destination through an independently confirmed channel before proceeding.",
    limitations: [
      "AheadGuard could not reach or complete the live investigation with the local backend.",
      "Absence of threat indicators is not proof of safety."
    ],
    eventsCount: 0
  };
}
async function investigateUrl(options) {
  const { url, backendUrl = DEFAULT_BACKEND_URL, onProgress, signal } = options;
  const validation = validateAndNormalizeUrl(url);
  if (!validation.valid) {
    throw new Error(validation.error);
  }
  const endpoint = `${backendUrl.replace(/\/+$/, "")}/api/investigate`;
  const timeoutSignal = AbortSignal.timeout(115e3);
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
  onProgress?.("Connecting to AheadGuard backend\u2026");
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream, application/json"
      },
      body: JSON.stringify({ input: validation.normalizedUrl }),
      signal: combinedSignal
    });
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("text/event-stream") && response.body) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let finalReport;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let splitIdx;
        while ((splitIdx = buffer.search(/\r?\n\r?\n/)) >= 0) {
          const chunk = buffer.slice(0, splitIdx);
          const delimiter = buffer.slice(splitIdx).match(/^\r?\n\r?\n/)?.[0] ?? "\n\n";
          buffer = buffer.slice(splitIdx + delimiter.length);
          let eventType = "message";
          const dataLines = [];
          for (const line of chunk.split(/\r?\n/)) {
            if (line.startsWith("event:")) eventType = line.slice(6).trim();
            if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
          }
          if (!dataLines.length) continue;
          const dataText = dataLines.join("\n");
          try {
            const parsed = JSON.parse(dataText);
            if (eventType === "started" || eventType === "progress") {
              onProgress?.(parsed.message || "Investigating page\u2026");
            } else if (eventType === "streaming_url") {
              onProgress?.("Remote browser session live\u2026");
            } else if (eventType === "complete") {
              onProgress?.("Evaluating returned evidence\u2026");
            } else if (eventType === "report") {
              finalReport = parsed.report || parsed;
            } else if (eventType === "error") {
              if (parsed.report) return parsed.report;
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
    const data = await response.json().catch(() => {
      throw new Error(`Failed to parse backend response (HTTP ${response.status}).`);
    });
    if (!response.ok) {
      if (data.report) return data.report;
      throw new Error(data.error || `Backend returned HTTP ${response.status}.`);
    }
    if (data.report) {
      return data.report;
    }
    throw new Error("Backend response did not contain an investigation report.");
  } catch (error) {
    const isTimeout = combinedSignal.aborted;
    const cleanMsg = isTimeout ? "Investigation timed out. The destination could not be validated." : sanitizeClientMessage(error);
    return createUnknownReport(validation.normalizedUrl, cleanMsg);
  }
}

// extension/src/background.ts
var DEFAULT_SETTINGS = {
  monitoringEnabled: true,
  historyPaused: false,
  backendUrl: DEFAULT_BACKEND_URL
};
var tabStates = /* @__PURE__ */ new Map();
var recentChecks = /* @__PURE__ */ new Map();
var DEDUPE_COOLDOWN_MS = 5 * 60 * 1e3;
function isSupportedUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}
async function getSettings() {
  const data = await chrome.storage.local.get(["monitoringEnabled", "historyPaused", "backendUrl"]);
  return {
    monitoringEnabled: typeof data.monitoringEnabled === "boolean" ? data.monitoringEnabled : DEFAULT_SETTINGS.monitoringEnabled,
    historyPaused: typeof data.historyPaused === "boolean" ? data.historyPaused : DEFAULT_SETTINGS.historyPaused,
    backendUrl: typeof data.backendUrl === "string" ? data.backendUrl : DEFAULT_SETTINGS.backendUrl
  };
}
async function updateBadge(tabId, report) {
  try {
    if (!report) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    switch (report.riskOutcome) {
      case "High risk":
        await chrome.action.setBadgeText({ tabId, text: "!" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#FF4D4D" });
        break;
      case "Suspicious":
        await chrome.action.setBadgeText({ tabId, text: "!" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#FFAA00" });
        break;
      case "Low observed risk":
        await chrome.action.setBadgeText({ tabId, text: "\u2713" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#00CC88" });
        break;
      case "Unknown":
      default:
        await chrome.action.setBadgeText({ tabId, text: "?" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#3388CC" });
        break;
    }
  } catch {
  }
}
async function appendToLedger(report) {
  const settings = await getSettings();
  if (settings.historyPaused) return;
  try {
    const data = await chrome.storage.local.get("aheadguard_ledger");
    const existing = Array.isArray(data.aheadguard_ledger) ? data.aheadguard_ledger : [];
    const newItem = {
      investigationId: report.investigationId,
      timestamp: report.timestamp,
      url: report.originalUrl,
      host: report.observedDestination.submittedHost,
      riskOutcome: report.riskOutcome,
      summary: report.outcomeReason,
      proposedAction: report.actionPreview.proposedAction,
      finalUrl: report.observedDestination.finalUrl
    };
    const updated = [newItem, ...existing.filter((item) => item.investigationId !== report.investigationId)].slice(
      0,
      25
    );
    await chrome.storage.local.set({ aheadguard_ledger: updated });
  } catch {
  }
}
async function performInvestigation(tabId, url) {
  const state = {
    url,
    isSupportedScheme: isSupportedUrl(url),
    isChecking: true
  };
  tabStates.set(tabId, state);
  const cached = recentChecks.get(url);
  if (cached && Date.now() - cached.timestamp < DEDUPE_COOLDOWN_MS) {
    state.isChecking = false;
    state.activeReport = cached.report;
    tabStates.set(tabId, state);
    await updateBadge(tabId, cached.report);
    return cached.report;
  }
  const settings = await getSettings();
  try {
    const report = await investigateUrl({
      url,
      backendUrl: settings.backendUrl
    });
    state.isChecking = false;
    state.activeReport = report;
    tabStates.set(tabId, state);
    recentChecks.set(url, { timestamp: Date.now(), report });
    await updateBadge(tabId, report);
    await appendToLedger(report);
    return report;
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : "Investigation failed.";
    state.isChecking = false;
    state.error = errorMsg;
    tabStates.set(tabId, state);
    throw err;
  }
}
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(["monitoringEnabled", "historyPaused", "backendUrl"]);
  await chrome.storage.local.set({
    monitoringEnabled: current.monitoringEnabled ?? DEFAULT_SETTINGS.monitoringEnabled,
    historyPaused: current.historyPaused ?? DEFAULT_SETTINGS.historyPaused,
    backendUrl: current.backendUrl ?? DEFAULT_SETTINGS.backendUrl
  });
});
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  const isSupported = isSupportedUrl(url);
  tabStates.set(details.tabId, {
    url,
    isSupportedScheme: isSupported,
    isChecking: false
  });
  if (!isSupported) {
    await updateBadge(details.tabId, void 0);
    return;
  }
  const settings = await getSettings();
  if (!settings.monitoringEnabled) {
    await updateBadge(details.tabId, void 0);
    return;
  }
  const cached = recentChecks.get(url);
  if (cached && Date.now() - cached.timestamp < DEDUPE_COOLDOWN_MS) {
    const state = tabStates.get(details.tabId) || { isSupportedScheme: true, isChecking: false };
    state.activeReport = cached.report;
    tabStates.set(details.tabId, state);
    await updateBadge(details.tabId, cached.report);
  } else {
    await updateBadge(details.tabId, void 0);
  }
});
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!sender.id || chrome.runtime?.id && sender.id !== chrome.runtime.id) {
    sendResponse({ error: "Unauthorized message sender." });
    return false;
  }
  if (!message || typeof message !== "object" || !("type" in message)) {
    sendResponse({ error: "Invalid extension message format." });
    return false;
  }
  const msg = message;
  (async () => {
    switch (msg.type) {
      case "GET_STATUS": {
        let targetTabId = msg.tabId;
        if (!targetTabId) {
          const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
          targetTabId = activeTab?.id;
        }
        const settings = await getSettings();
        if (!targetTabId) {
          sendResponse({
            isSupportedScheme: false,
            monitoringEnabled: settings.monitoringEnabled,
            historyPaused: settings.historyPaused,
            isChecking: false
          });
          return;
        }
        const state = tabStates.get(targetTabId);
        const [tabInfo] = await chrome.tabs.query({ active: true, currentWindow: true });
        const currentUrl = state?.url || tabInfo?.url;
        sendResponse({
          tabId: targetTabId,
          url: currentUrl,
          isSupportedScheme: isSupportedUrl(currentUrl),
          monitoringEnabled: settings.monitoringEnabled,
          historyPaused: settings.historyPaused,
          activeReport: state?.activeReport,
          isChecking: state?.isChecking ?? false,
          error: state?.error
        });
        break;
      }
      case "CHECK_URL": {
        if (!msg.url || typeof msg.url !== "string" || !isSupportedUrl(msg.url)) {
          sendResponse({ success: false, error: "Invalid or unsupported target URL." });
          break;
        }
        let tabId = msg.tabId;
        if (!tabId) {
          const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
          tabId = activeTab?.id ?? -1;
        }
        try {
          const report = await performInvestigation(tabId, msg.url);
          sendResponse({ success: true, report });
        } catch (err) {
          const error = err instanceof Error ? err.message : "Investigation failed.";
          sendResponse({ success: false, error });
        }
        break;
      }
      case "GET_SETTINGS": {
        const settings = await getSettings();
        sendResponse(settings);
        break;
      }
      case "UPDATE_SETTINGS": {
        if (!msg.settings || typeof msg.settings !== "object") {
          sendResponse({ success: false, error: "Invalid settings payload." });
          break;
        }
        const current = await getSettings();
        const updated = {
          monitoringEnabled: typeof msg.settings.monitoringEnabled === "boolean" ? msg.settings.monitoringEnabled : current.monitoringEnabled,
          historyPaused: typeof msg.settings.historyPaused === "boolean" ? msg.settings.historyPaused : current.historyPaused,
          backendUrl: typeof msg.settings.backendUrl === "string" && isValidBackendEndpoint(msg.settings.backendUrl) ? msg.settings.backendUrl : current.backendUrl
        };
        await chrome.storage.local.set(updated);
        sendResponse({ success: true, settings: updated });
        break;
      }
      case "CLEAR_LEDGER": {
        await chrome.storage.local.remove("aheadguard_ledger");
        sendResponse({ success: true });
        break;
      }
      case "GET_LEDGER": {
        const data = await chrome.storage.local.get("aheadguard_ledger");
        sendResponse({ ledger: Array.isArray(data.aheadguard_ledger) ? data.aheadguard_ledger : [] });
        break;
      }
      case "NAVIGATE_TAB": {
        if (!msg.url || typeof msg.url !== "string" || !isSupportedUrl(msg.url)) {
          sendResponse({ success: false, error: "Invalid or unsupported target URL." });
          break;
        }
        let targetId = msg.tabId;
        if (!targetId) {
          const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
          targetId = activeTab?.id;
        }
        if (targetId) {
          await chrome.tabs.update(targetId, { url: msg.url });
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: "Missing tabId or target URL." });
        }
        break;
      }
      default:
        sendResponse({ error: "Unsupported message type." });
        break;
    }
  })();
  return true;
});
export {
  isValidBackendEndpoint
};
