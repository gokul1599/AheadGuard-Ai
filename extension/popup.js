// extension/src/config.ts
var PRODUCTION_BACKEND_URL = "https://aheadguard-ai.vercel.app";
var DEFAULT_BACKEND_URL = PRODUCTION_BACKEND_URL;

// extension/src/popup.ts
document.addEventListener("DOMContentLoaded", async () => {
  const activeUrlDisplay = document.getElementById("active-url-display");
  const unsupportedWarning = document.getElementById("unsupported-warning");
  const toggleManualInput = document.getElementById("toggle-manual-input");
  const customInputContainer = document.getElementById("custom-input-container");
  const customUrlInput = document.getElementById("custom-url-input");
  const checkBtn = document.getElementById("check-btn");
  const btnSpinner = document.getElementById("btn-spinner");
  const btnText = document.getElementById("btn-text");
  const progressContainer = document.getElementById("progress-container");
  const progressText = document.getElementById("progress-text");
  const resultContainer = document.getElementById("result-container");
  const riskBanner = document.getElementById("risk-banner");
  const riskIcon = document.getElementById("risk-icon");
  const riskTitle = document.getElementById("risk-title");
  const riskSummary = document.getElementById("risk-summary");
  const riskLikelihoodPill = document.getElementById("risk-likelihood-pill");
  const lowRiskDisclaimer = document.getElementById("low-risk-disclaimer");
  const previewProposed = document.getElementById("preview-proposed");
  const previewConsequence = document.getElementById("preview-consequence");
  const previewFactors = document.getElementById("preview-factors");
  const metaHost = document.getElementById("meta-host");
  const redirectWarning = document.getElementById("redirect-warning");
  const metaFinalHost = document.getElementById("meta-final-host");
  const evidenceCount = document.getElementById("evidence-count");
  const evidenceList = document.getElementById("evidence-list");
  const recText = document.getElementById("rec-text");
  const viewFullReport = document.getElementById("view-full-report");
  const safeNavigateBtn = document.getElementById("safe-navigate-btn");
  const settingsBtn = document.getElementById("settings-btn");
  const settingsDrawer = document.getElementById("settings-drawer");
  const closeSettings = document.getElementById("close-settings");
  const toggleMonitoring = document.getElementById("toggle-monitoring");
  const togglePauseLedger = document.getElementById("toggle-pause-ledger");
  const backendUrlInput = document.getElementById("backend-url-input");
  const clearLedgerBtn = document.getElementById("clear-ledger-btn");
  const ledgerList = document.getElementById("ledger-list");
  const ledgerCount = document.getElementById("ledger-count");
  const openWebApp = document.getElementById("open-web-app");
  let currentTabUrl;
  let activeTabId;
  let currentBackendUrl = DEFAULT_BACKEND_URL;
  try {
    const status = await chrome.runtime.sendMessage({ type: "GET_STATUS" });
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
  try {
    const settings = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (settings.backendUrl) {
      currentBackendUrl = settings.backendUrl;
      backendUrlInput.value = settings.backendUrl;
      openWebApp.href = settings.backendUrl;
    }
  } catch {
  }
  await loadLedger();
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
  settingsBtn.addEventListener("click", () => {
    settingsDrawer.classList.toggle("hidden");
  });
  closeSettings.addEventListener("click", () => {
    settingsDrawer.classList.add("hidden");
  });
  toggleMonitoring.addEventListener("change", async () => {
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { monitoringEnabled: toggleMonitoring.checked }
    });
  });
  togglePauseLedger.addEventListener("change", async () => {
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { historyPaused: togglePauseLedger.checked }
    });
  });
  backendUrlInput.addEventListener("change", async () => {
    const newUrl = backendUrlInput.value.trim() || DEFAULT_BACKEND_URL;
    currentBackendUrl = newUrl;
    openWebApp.href = newUrl;
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { backendUrl: newUrl }
    });
  });
  clearLedgerBtn.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "CLEAR_LEDGER" });
    await loadLedger();
  });
  safeNavigateBtn.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({
      type: "NAVIGATE_TAB",
      tabId: activeTabId,
      url: "https://www.google.com"
    });
    window.close();
  });
  checkBtn.addEventListener("click", async () => {
    const customUrl = customUrlInput.value.trim();
    const targetUrl = customUrl || currentTabUrl;
    if (!targetUrl) return;
    checkBtn.disabled = true;
    btnSpinner.classList.remove("hidden");
    btnText.textContent = "Investigating\u2026";
    progressContainer.classList.remove("hidden");
    progressText.textContent = "Initiating AheadGuard investigation\u2026";
    resultContainer.classList.add("hidden");
    try {
      const response = await chrome.runtime.sendMessage({
        type: "CHECK_URL",
        url: targetUrl,
        tabId: activeTabId
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
  function renderReport(report) {
    resultContainer.classList.remove("hidden");
    riskBanner.className = "risk-banner";
    let iconSymbol = "\u{1F6E1}\uFE0F";
    switch (report.riskOutcome) {
      case "High risk":
        riskBanner.classList.add("high");
        iconSymbol = "\u{1F6A8}";
        break;
      case "Suspicious":
        riskBanner.classList.add("suspicious");
        iconSymbol = "\u26A0\uFE0F";
        break;
      case "Low observed risk":
        riskBanner.classList.add("low");
        iconSymbol = "\u2705";
        break;
      case "Unknown":
      default:
        riskBanner.classList.add("unknown");
        iconSymbol = "\u2753";
        break;
    }
    riskIcon.textContent = iconSymbol;
    riskTitle.textContent = report.riskOutcome.toUpperCase();
    riskSummary.textContent = report.outcomeReason;
    riskLikelihoodPill.textContent = `Likelihood: ${report.threatLikelihood} \xB7 Impact: ${report.consequenceImpact}`;
    if (lowRiskDisclaimer) {
      if (report.riskOutcome === "Low observed risk") {
        lowRiskDisclaimer.classList.remove("hidden");
      } else {
        lowRiskDisclaimer.classList.add("hidden");
      }
    }
    previewProposed.textContent = report.actionPreview.proposedAction;
    previewConsequence.textContent = report.actionPreview.consequenceIfProceed;
    previewFactors.innerHTML = "";
    for (const factor of report.actionPreview.riskFactors) {
      const li = document.createElement("li");
      li.textContent = factor;
      previewFactors.appendChild(li);
    }
    metaHost.textContent = report.observedDestination.submittedHost;
    if (report.observedDestination.destinationChanged && report.observedDestination.finalHost) {
      metaFinalHost.textContent = report.observedDestination.finalHost;
      redirectWarning.classList.remove("hidden");
    } else {
      redirectWarning.classList.add("hidden");
    }
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
    recText.textContent = report.recommendedAction;
    const webUrl = `${currentBackendUrl.replace(/\/+$/, "")}/?url=${encodeURIComponent(report.originalUrl)}`;
    viewFullReport.href = webUrl;
  }
  async function loadLedger() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: "GET_LEDGER" });
      const items = resp?.ledger || [];
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
        hostSpan.textContent = `${item.host} (${new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })})`;
        row.appendChild(hostSpan);
        const badgeSpan = document.createElement("span");
        badgeSpan.className = "pill";
        badgeSpan.textContent = item.riskOutcome;
        badgeSpan.style.borderColor = item.riskOutcome === "High risk" ? "var(--red)" : item.riskOutcome === "Suspicious" ? "var(--amber)" : item.riskOutcome === "Low observed risk" ? "var(--green)" : "var(--cyan)";
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
    }
  }
});
