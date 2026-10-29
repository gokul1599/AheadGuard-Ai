import type {
  InvestigationReport,
  TabStatusResponse,
  ExtensionSettings,
  ExtensionLedgerItem,
} from "./types";
import { DEFAULT_BACKEND_URL } from "./config";

document.addEventListener("DOMContentLoaded", async () => {
  // Elements
  const activeUrlDisplay = document.getElementById("active-url-display") as HTMLDivElement;
  const unsupportedWarning = document.getElementById("unsupported-warning") as HTMLDivElement;
  const toggleManualInput = document.getElementById("toggle-manual-input") as HTMLButtonElement;
  const customInputContainer = document.getElementById("custom-input-container") as HTMLDivElement;
  const customUrlInput = document.getElementById("custom-url-input") as HTMLInputElement;
  const checkBtn = document.getElementById("check-btn") as HTMLButtonElement;
  const btnSpinner = document.getElementById("btn-spinner") as HTMLSpanElement;
  const btnText = document.getElementById("btn-text") as HTMLSpanElement;
  const progressContainer = document.getElementById("progress-container") as HTMLDivElement;
  const progressText = document.getElementById("progress-text") as HTMLDivElement;

  // Result Elements
  const resultContainer = document.getElementById("result-container") as HTMLDivElement;
  const riskBanner = document.getElementById("risk-banner") as HTMLDivElement;
  const riskIcon = document.getElementById("risk-icon") as HTMLDivElement;
  const riskTitle = document.getElementById("risk-title") as HTMLHeadingElement;
  const riskSummary = document.getElementById("risk-summary") as HTMLParagraphElement;
  const riskLikelihoodPill = document.getElementById("risk-likelihood-pill") as HTMLSpanElement;
  const lowRiskDisclaimer = document.getElementById("low-risk-disclaimer") as HTMLDivElement | null;
  const previewProposed = document.getElementById("preview-proposed") as HTMLSpanElement;
  const previewConsequence = document.getElementById("preview-consequence") as HTMLParagraphElement;
  const previewFactors = document.getElementById("preview-factors") as HTMLUListElement;
  const metaHost = document.getElementById("meta-host") as HTMLElement;
  const redirectWarning = document.getElementById("redirect-warning") as HTMLDivElement;
  const metaFinalHost = document.getElementById("meta-final-host") as HTMLElement;
  const evidenceCount = document.getElementById("evidence-count") as HTMLSpanElement;
  const evidenceList = document.getElementById("evidence-list") as HTMLDivElement;
  const recText = document.getElementById("rec-text") as HTMLParagraphElement;
  const viewFullReport = document.getElementById("view-full-report") as HTMLAnchorElement;
  const safeNavigateBtn = document.getElementById("safe-navigate-btn") as HTMLButtonElement;

  // Settings & Ledger Elements
  const settingsBtn = document.getElementById("settings-btn") as HTMLButtonElement;
  const settingsDrawer = document.getElementById("settings-drawer") as HTMLDivElement;
  const closeSettings = document.getElementById("close-settings") as HTMLButtonElement;
  const toggleMonitoring = document.getElementById("toggle-monitoring") as HTMLInputElement;
  const togglePauseLedger = document.getElementById("toggle-pause-ledger") as HTMLInputElement;
  const backendUrlInput = document.getElementById("backend-url-input") as HTMLInputElement;
  const clearLedgerBtn = document.getElementById("clear-ledger-btn") as HTMLButtonElement;
  const ledgerList = document.getElementById("ledger-list") as HTMLDivElement;
  const ledgerCount = document.getElementById("ledger-count") as HTMLSpanElement;
  const openWebApp = document.getElementById("open-web-app") as HTMLAnchorElement;

  let currentTabUrl: string | undefined;
  let activeTabId: number | undefined;
  let currentBackendUrl = DEFAULT_BACKEND_URL;

  // 1. Load initial status from background service worker
  try {
    const status: TabStatusResponse = await chrome.runtime.sendMessage({ type: "GET_STATUS" });
    currentTabUrl = status.url;
    activeTabId = status.tabId;

    if (currentTabUrl) {
      activeUrlDisplay.textContent = currentTabUrl;
    } else {
      activeUrlDisplay.textContent = "No active page detected";
    }

    if (!status.isSupportedScheme) {
      unsupportedWarning.classList.remove("hidden");
      checkBtn.disabled = true;
    } else {
      unsupportedWarning.classList.add("hidden");
      checkBtn.disabled = false;
    }

    toggleMonitoring.checked = status.monitoringEnabled;
    togglePauseLedger.checked = status.historyPaused;

    if (status.activeReport) {
      renderReport(status.activeReport);
    }
  } catch {
    activeUrlDisplay.textContent = "AheadGuard background service offline";
    checkBtn.disabled = true;
  }

  // 2. Load settings and ledger
  try {
    const settings: ExtensionSettings = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (settings.backendUrl) {
      currentBackendUrl = settings.backendUrl;
      backendUrlInput.value = settings.backendUrl;
      openWebApp.href = settings.backendUrl;
    }
  } catch {
    // Non-fatal
  }

  await loadLedger();

  // 3. Toggle Custom URL input
  toggleManualInput.addEventListener("click", () => {
    const isHidden = customInputContainer.classList.contains("hidden");
    if (isHidden) {
      customInputContainer.classList.remove("hidden");
      toggleManualInput.textContent = "Use active tab URL";
      customUrlInput.focus();
      if (customUrlInput.value.trim().length >= 4) {
        checkBtn.disabled = false;
      }
    } else {
      customInputContainer.classList.add("hidden");
      toggleManualInput.textContent = "Check custom link";
      customUrlInput.value = "";
      if (!unsupportedWarning.classList.contains("hidden")) {
        checkBtn.disabled = true;
      }
    }
  });

  customUrlInput.addEventListener("input", () => {
    const val = customUrlInput.value.trim();
    if (val.length >= 4) {
      checkBtn.disabled = false;
    } else if (!unsupportedWarning.classList.contains("hidden")) {
      checkBtn.disabled = true;
    }
  });

  // 4. Settings Drawer toggling
  settingsBtn.addEventListener("click", () => {
    settingsDrawer.classList.toggle("hidden");
  });

  closeSettings.addEventListener("click", () => {
    settingsDrawer.classList.add("hidden");
  });

  toggleMonitoring.addEventListener("change", async () => {
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { monitoringEnabled: toggleMonitoring.checked },
    });
  });

  togglePauseLedger.addEventListener("change", async () => {
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { historyPaused: togglePauseLedger.checked },
    });
  });

  backendUrlInput.addEventListener("change", async () => {
    const newUrl = backendUrlInput.value.trim() || DEFAULT_BACKEND_URL;
    currentBackendUrl = newUrl;
    openWebApp.href = newUrl;
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { backendUrl: newUrl },
    });
  });

  clearLedgerBtn.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "CLEAR_LEDGER" });
    await loadLedger();
  });

  // 5. Safe Navigate away action
  safeNavigateBtn.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({
      type: "NAVIGATE_TAB",
      tabId: activeTabId,
      url: "https://www.google.com",
    });
    window.close();
  });

  // 6. Trigger Investigation
  checkBtn.addEventListener("click", async () => {
    const customUrl = customUrlInput.value.trim();
    const targetUrl = customUrl || currentTabUrl;

    if (!targetUrl) return;

    // UI Loading state
    checkBtn.disabled = true;
    btnSpinner.classList.remove("hidden");
    btnText.textContent = "Investigating…";
    progressContainer.classList.remove("hidden");
    progressText.textContent = "Initiating AheadGuard investigation…";
    resultContainer.classList.add("hidden");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "CHECK_URL",
        url: targetUrl,
        tabId: activeTabId,
      });

      if (!response.success || !response.report) {
        throw new Error(response.error || "Investigation did not return a report.");
      }

      renderReport(response.report);
      await loadLedger();
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Investigation failed.";
      progressText.textContent = `Error: ${errMsg}`;
    } finally {
      checkBtn.disabled = false;
      btnSpinner.classList.add("hidden");
      btnText.textContent = "Investigate Destination";
      setTimeout(() => {
        progressContainer.classList.add("hidden");
      }, 800);
    }
  });

  // 7. Render Report Helper
  function renderReport(report: InvestigationReport) {
    resultContainer.classList.remove("hidden");

    // Outcome class
    riskBanner.className = "risk-banner";
    let iconSymbol = "🛡️";

    switch (report.riskOutcome) {
      case "High risk":
        riskBanner.classList.add("high");
        iconSymbol = "🚨";
        break;
      case "Suspicious":
        riskBanner.classList.add("suspicious");
        iconSymbol = "⚠️";
        break;
      case "Low observed risk":
        riskBanner.classList.add("low");
        iconSymbol = "✅";
        break;
      case "Unknown":
      default:
        riskBanner.classList.add("unknown");
        iconSymbol = "❓";
        break;
    }

    riskIcon.textContent = iconSymbol;
    riskTitle.textContent = report.riskOutcome.toUpperCase();
    riskSummary.textContent = report.outcomeReason;
    riskLikelihoodPill.textContent = `Likelihood: ${report.threatLikelihood} · Impact: ${report.consequenceImpact}`;

    if (lowRiskDisclaimer) {
      if (report.riskOutcome === "Low observed risk") {
        lowRiskDisclaimer.classList.remove("hidden");
      } else {
        lowRiskDisclaimer.classList.add("hidden");
      }
    }

    // Action Preview
    previewProposed.textContent = report.actionPreview.proposedAction;
    previewConsequence.textContent = report.actionPreview.consequenceIfProceed;

    previewFactors.innerHTML = "";
    for (const factor of report.actionPreview.riskFactors) {
      const li = document.createElement("li");
      li.textContent = factor;
      previewFactors.appendChild(li);
    }

    // Host & Redirects
    metaHost.textContent = report.observedDestination.submittedHost;
    if (report.observedDestination.destinationChanged && report.observedDestination.finalHost) {
      metaFinalHost.textContent = report.observedDestination.finalHost;
      redirectWarning.classList.remove("hidden");
    } else {
      redirectWarning.classList.add("hidden");
    }

    // Evidence Items
    evidenceCount.textContent = String(report.evidenceItems.length);
    evidenceList.innerHTML = "";

    for (const item of report.evidenceItems) {
      const div = document.createElement("div");
      div.className = `evidence-item ${item.kind}`;

      const textSpan = document.createElement("span");
      textSpan.textContent = `${item.label}: ${item.detail}`;
      div.appendChild(textSpan);

      const tagSpan = document.createElement("span");
      tagSpan.className = "provenance-tag";
      tagSpan.textContent = item.provenance.replace("_", " ");
      div.appendChild(tagSpan);

      evidenceList.appendChild(div);
    }

    if (report.evidenceItems.length === 0) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "empty-ledger";
      emptyDiv.textContent = "No specific warning items observed.";
      evidenceList.appendChild(emptyDiv);
    }

    // Recommendation
    recText.textContent = report.recommendedAction;

    // Full Report Link
    const webUrl =
      report.originalUrl && report.originalUrl.startsWith("http")
        ? `${currentBackendUrl.replace(/\/+$/, "")}/?url=${encodeURIComponent(report.originalUrl)}`
        : `${currentBackendUrl.replace(/\/+$/, "")}/?id=${encodeURIComponent(report.investigationId)}`;
    viewFullReport.href = webUrl;
  }

  // 8. Load Ledger Helper
  async function loadLedger() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: "GET_LEDGER" });
      const items: ExtensionLedgerItem[] = resp?.ledger || [];

      ledgerCount.textContent = `${items.length} record(s)`;
      ledgerList.innerHTML = "";

      if (items.length === 0) {
        ledgerList.innerHTML = '<div class="empty-ledger">No recent investigations recorded.</div>';
        return;
      }

      for (const item of items) {
        const row = document.createElement("div");
        row.className = "ledger-item";

        const hostSpan = document.createElement("span");
        hostSpan.className = "ledger-host";
        hostSpan.textContent = `${item.host} (${new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})`;
        row.appendChild(hostSpan);

        const badgeSpan = document.createElement("span");
        badgeSpan.className = "pill";
        badgeSpan.textContent = item.riskOutcome;
        badgeSpan.style.borderColor =
          item.riskOutcome === "High risk"
            ? "var(--red)"
            : item.riskOutcome === "Suspicious"
            ? "var(--amber)"
            : item.riskOutcome === "Low observed risk"
            ? "var(--green)"
            : "var(--cyan)";
        row.appendChild(badgeSpan);

        row.addEventListener("click", () => {
          customUrlInput.value = item.url;
          customInputContainer.classList.remove("hidden");
          toggleManualInput.textContent = "Use active tab URL";
          checkBtn.click();
        });

        ledgerList.appendChild(row);
      }
    } catch {
      // Ledger loading error
    }
  }
});
