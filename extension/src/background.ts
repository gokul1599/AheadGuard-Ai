import type {
  ExtensionMessage,
  ExtensionSettings,
  ExtensionLedgerItem,
  InvestigationReport,
  TabStatusResponse,
} from "./types";
import { investigateUrl } from "./api-client";

const DEFAULT_SETTINGS: ExtensionSettings = {
  monitoringEnabled: true,
  historyPaused: false,
  backendUrl: "http://localhost:3000",
};

// In-memory tab state and deduplication cache
interface TabState {
  url?: string;
  isSupportedScheme: boolean;
  isChecking: boolean;
  activeReport?: InvestigationReport;
  error?: string;
}

const tabStates = new Map<number, TabState>();
const recentChecks = new Map<string, { timestamp: number; report: InvestigationReport }>();
const DEDUPE_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes

function isSupportedUrl(url?: string): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidBackendEndpoint(url?: string): boolean {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    if (parsed.username || parsed.password) return false;
    const host = parsed.hostname.toLowerCase();
    // Allow local development endpoints
    if (host === "localhost" || host === "127.0.0.1") return true;
    return false;
  } catch {
    return false;
  }
}

async function getSettings(): Promise<ExtensionSettings> {
  const data = (await chrome.storage.local.get(["monitoringEnabled", "historyPaused", "backendUrl"])) as {
    monitoringEnabled?: boolean;
    historyPaused?: boolean;
    backendUrl?: string;
  };
  return {
    monitoringEnabled: typeof data.monitoringEnabled === "boolean" ? data.monitoringEnabled : DEFAULT_SETTINGS.monitoringEnabled,
    historyPaused: typeof data.historyPaused === "boolean" ? data.historyPaused : DEFAULT_SETTINGS.historyPaused,
    backendUrl: typeof data.backendUrl === "string" ? data.backendUrl : DEFAULT_SETTINGS.backendUrl,
  };
}

async function updateBadge(tabId: number, report?: InvestigationReport) {
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
        await chrome.action.setBadgeText({ tabId, text: "✓" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#00CC88" });
        break;
      case "Unknown":
      default:
        await chrome.action.setBadgeText({ tabId, text: "?" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#3388CC" });
        break;
    }
  } catch {
    // Non-fatal if tab closed
  }
}

async function appendToLedger(report: InvestigationReport) {
  const settings = await getSettings();
  if (settings.historyPaused) return;

  try {
    const data = await chrome.storage.local.get("aheadguard_ledger");
    const existing: ExtensionLedgerItem[] = Array.isArray(data.aheadguard_ledger) ? data.aheadguard_ledger : [];

    const newItem: ExtensionLedgerItem = {
      investigationId: report.investigationId,
      timestamp: report.timestamp,
      url: report.originalUrl,
      host: report.observedDestination.submittedHost,
      riskOutcome: report.riskOutcome,
      summary: report.outcomeReason,
      proposedAction: report.actionPreview.proposedAction,
      finalUrl: report.observedDestination.finalUrl,
    };

    const updated = [newItem, ...existing.filter((item) => item.investigationId !== report.investigationId)].slice(
      0,
      25
    );
    await chrome.storage.local.set({ aheadguard_ledger: updated });
  } catch {
    // Local storage access error
  }
}

async function performInvestigation(tabId: number, url: string): Promise<InvestigationReport> {
  const state: TabState = {
    url,
    isSupportedScheme: isSupportedUrl(url),
    isChecking: true,
  };
  tabStates.set(tabId, state);

  // Check in-memory deduplication cache
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
      backendUrl: settings.backendUrl,
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

// 1. Initialize settings on extension install
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(["monitoringEnabled", "historyPaused", "backendUrl"]);
  await chrome.storage.local.set({
    monitoringEnabled: current.monitoringEnabled ?? DEFAULT_SETTINGS.monitoringEnabled,
    historyPaused: current.historyPaused ?? DEFAULT_SETTINGS.historyPaused,
    backendUrl: current.backendUrl ?? DEFAULT_SETTINGS.backendUrl,
  });
});

// 2. Navigation awareness via chrome.webNavigation.onCommitted
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only monitor top-level frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;
  const isSupported = isSupportedUrl(url);

  tabStates.set(details.tabId, {
    url,
    isSupportedScheme: isSupported,
    isChecking: false,
  });

  if (!isSupported) {
    await updateBadge(details.tabId, undefined);
    return;
  }

  const settings = await getSettings();
  if (!settings.monitoringEnabled) {
    await updateBadge(details.tabId, undefined);
    return;
  }

  // Check cache for this destination to show immediate status badge
  const cached = recentChecks.get(url);
  if (cached && Date.now() - cached.timestamp < DEDUPE_COOLDOWN_MS) {
    const state = tabStates.get(details.tabId) || { isSupportedScheme: true, isChecking: false };
    state.activeReport = cached.report;
    tabStates.set(details.tabId, state);
    await updateBadge(details.tabId, cached.report);
  } else {
    await updateBadge(details.tabId, undefined);
  }
});

// Clean up tab state on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

// 3. Centralized Message Handling
chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  // Validate sender ID to prevent external message injection
  if (!sender.id || (chrome.runtime?.id && sender.id !== chrome.runtime.id)) {
    sendResponse({ error: "Unauthorized message sender." });
    return false;
  }

  if (!message || typeof message !== "object" || !("type" in message)) {
    sendResponse({ error: "Invalid extension message format." });
    return false;
  }

  const msg = message as ExtensionMessage;

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
            isChecking: false,
          } as TabStatusResponse);
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
          error: state?.error,
        } as TabStatusResponse);
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
        const updated: ExtensionSettings = {
          monitoringEnabled:
            typeof msg.settings.monitoringEnabled === "boolean"
              ? msg.settings.monitoringEnabled
              : current.monitoringEnabled,
          historyPaused:
            typeof msg.settings.historyPaused === "boolean" ? msg.settings.historyPaused : current.historyPaused,
          backendUrl:
            typeof msg.settings.backendUrl === "string" && isValidBackendEndpoint(msg.settings.backendUrl)
              ? msg.settings.backendUrl
              : current.backendUrl,
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

  return true; // Keep message channel open for async response
});
