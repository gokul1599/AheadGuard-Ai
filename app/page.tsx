"use client";

import { useState, useEffect, useRef } from "react";
import type { ReactNode } from "react";
import type { InvestigationReport, ClaimEvaluation } from "@/lib/types";
import { createShareableReport, formatReportMarkdown, formatReportSummary } from "@/lib/share-report";
import { extractUrlsFromText } from "@/lib/message-intelligence";
import { DEMO_SCENARIOS, getDemoScenario, isDemoReport } from "@/lib/demo-data";
import { TrustGapMap } from "@/components/TrustGapMap";
import { EvidenceCoverageCard } from "@/components/EvidenceCoverageCard";

type AnalysisMode = "link" | "message" | "job" | "report";

const LINK_EXAMPLES = [
  { label: "Scaler Official", value: "https://www.scaler.com" },
  { label: "Wikipedia", value: "https://en.wikipedia.org/wiki/Computer_security" },
  { label: "Phishing / Urgent Alert", value: "https://portal-account-verify.online/login?action=verify_now" },
  { label: "Lookalike Punycode", value: "https://xn--gogle-pra.com/signin" },
];

const MESSAGE_EXAMPLES = [
  {
    label: "WhatsApp Job Scam (Registration Fee)",
    value: "Congratulations! You are shortlisted for Google Cloud Operations Lead. Salary is $12,000/month. To confirm your interview slot, please pay a refundable registration fee of $50 via UPI to recruitment.team@okaxis. Apply here: https://careers-google-verify.top/apply",
  },
  {
    label: "Tech Support Alert (Password & OTP)",
    value: "URGENT: Your Microsoft 365 license will be terminated in 24 hours due to suspicious activity. Reply immediately with your current password and 6-digit OTP code to avoid total account deletion: https://security-microsoft-update.net/auth",
  },
  {
    label: "Part-Time Task Scam (Multi-Link)",
    value: "Earn $500/day by reviewing YouTube videos from home! No experience required. Official info at https://google.com and register your task wallet at https://fast-payout-tasks.xyz/register.",
  },
];

const JOB_EXAMPLES = [
  {
    label: "Amazon AWS Architect (Official)",
    org: "Amazon",
    role: "Senior Solutions Architect",
    comp: "$195,000/year",
    recruiter: "Amazon Talent Acquisition",
    url: "https://amazon.jobs/en/jobs/2501234/senior-solutions-architect",
    careersUrl: "https://amazon.jobs",
  },
  {
    label: "Netflix Entry-Level (Lookalike + Security Deposit)",
    org: "Netflix",
    role: "Junior Content Reviewer",
    comp: "$80/hr remote",
    recruiter: "David Miller (Telegram: @netflix_hiring)",
    url: "https://netflix-careers-portal.online/application",
    careersUrl: "https://jobs.netflix.com",
    notes: "Mandatory $150 refundable equipment security deposit required prior to dispatching review laptop.",
  },
];

export default function Home() {
  // Mode selection
  const [mode, setMode] = useState<AnalysisMode>("link");

  // Input states
  const [linkInput, setLinkInput] = useState("");
  const [contextMessage, setContextMessage] = useState("");
  const [showContextMessage, setShowContextMessage] = useState(false);

  const [messageInput, setMessageInput] = useState("");
  const [messageTargetUrl, setMessageTargetUrl] = useState("");

  const [jobOrg, setJobOrg] = useState("");
  const [jobRole, setJobRole] = useState("");
  const [jobComp, setJobComp] = useState("");
  const [jobRecruiter, setJobRecruiter] = useState("");
  const [jobUrl, setJobUrl] = useState("");
  const [jobCareersOverride, setJobCareersOverride] = useState("");
  const [jobOfferText, setJobOfferText] = useState("");

  const [reportJsonInput, setReportJsonInput] = useState("");

  // Investigation execution states
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("Ready for digital trust & scam verification");
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [result, setResult] = useState<InvestigationReport | null>(null);
  const [streamingUrl, setStreamingUrl] = useState<string | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [activeTab, setActiveTab] = useState<"trustgap" | "intel" | "claims" | "routes" | "evidence" | "facts" | "checks">("trustgap");
  const [claimFilter, setClaimFilter] = useState<ClaimEvaluation | "All">("All");
  const [activeDemoScenarioId, setActiveDemoScenarioId] = useState<string | null>(null);

  // Multi-URL modal state
  const [showMultiUrlModal, setShowMultiUrlModal] = useState(false);
  const [detectedUrls, setDetectedUrls] = useState<string[]>([]);
  const [selectedMultiUrl, setSelectedMultiUrl] = useState<string>("");
  const [pendingMessagePayload, setPendingMessagePayload] = useState<Record<string, unknown> | null>(null);

  // Share report modal state
  const [showShareModal, setShowShareModal] = useState(false);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);

  // Evidence Ledger state (localStorage)
  const [history, setHistory] = useState<InvestigationReport[]>([]);
  const [isHistoryPaused, setIsHistoryPaused] = useState(false);
  const progressBoxRef = useRef<HTMLDivElement>(null);

  // Load ledger on mount & check for URL query params (deep-link support)
  useEffect(() => {
    let parsedHistory: InvestigationReport[] = [];
    try {
      const stored = localStorage.getItem("aheadguard_evidence_ledger_v1");
      if (stored) {
        parsedHistory = JSON.parse(stored);
        setHistory(parsedHistory);
      }
      const paused = localStorage.getItem("aheadguard_history_paused");
      if (paused === "true") {
        setIsHistoryPaused(true);
      }
    } catch {
      // LocalStorage access issues
    }

    try {
      const params = new URLSearchParams(window.location.search);
      const urlParam = params.get("url") || params.get("target");
      if (urlParam) {
        const decoded = decodeURIComponent(urlParam).trim();
        setLinkInput(decoded);
        setMode("link");

        const existing = parsedHistory.find(
          (r) =>
            r.originalUrl.toLowerCase() === decoded.toLowerCase() ||
            r.observedDestination?.submittedUrl?.toLowerCase() === decoded.toLowerCase() ||
            r.observedDestination?.normalizedUrl?.toLowerCase() === decoded.toLowerCase() ||
            (r.observedDestination?.finalUrl && r.observedDestination.finalUrl.toLowerCase() === decoded.toLowerCase())
        );
        if (existing) {
          setResult(existing);
          setStatus("Loaded verified report from Evidence Ledger.");
        }
      }
    } catch {
      // URL parsing issues
    }
  }, []);

  const handleSelectDemoScenario = (scenarioId: string) => {
    const scen = getDemoScenario(scenarioId);
    if (!scen) return;
    setResult(JSON.parse(JSON.stringify(scen.report)));
    setActiveDemoScenarioId(scen.id);
    setStatus(`Loaded offline demonstration scenario: ${scen.name}`);
    setError(null);
    setProgressLog([]);
    setLoading(false);
    setActiveTab("trustgap");

    // Scroll smoothly to results
    if (typeof window !== "undefined") {
      setTimeout(() => {
        const assessmentEl = document.querySelector(".assessment-container");
        if (assessmentEl) {
          assessmentEl.scrollIntoView({ behavior: "smooth" });
        }
      }, 50);
    }
  };

  const handleExitDemoMode = () => {
    setResult(null);
    setActiveDemoScenarioId(null);
    setStatus("Ready for digital trust & scam verification");
  };

  const saveToLedger = (report: InvestigationReport) => {
    if (isHistoryPaused) return;
    if (report.isDemo) return; // Do not save offline demo reports to real evidence history
    try {
      setHistory((prev) => {
        const filtered = prev.filter((item) => item.investigationId !== report.investigationId);
        const updated = [report, ...filtered].slice(0, 15);
        localStorage.setItem("aheadguard_evidence_ledger_v1", JSON.stringify(updated));
        return updated;
      });
    } catch {
      // LocalStorage error
    }
  };

  const clearLedger = () => {
    try {
      localStorage.removeItem("aheadguard_evidence_ledger_v1");
      setHistory([]);
    } catch {
      // LocalStorage error
    }
  };

  const toggleHistoryPause = () => {
    const nextState = !isHistoryPaused;
    setIsHistoryPaused(nextState);
    try {
      localStorage.setItem("aheadguard_history_paused", String(nextState));
    } catch {
      // LocalStorage error
    }
  };

  // Main Investigation Handler
  async function runInvestigation(overridePayload?: Record<string, unknown>) {
    if (loading) return;

    // Build payload according to current active mode
    let payload: Record<string, unknown> = {};

    if (overridePayload) {
      payload = overridePayload;
    } else if (mode === "link") {
      if (!linkInput.trim()) return;
      payload = {
        input: linkInput.trim(),
        messageText: showContextMessage && contextMessage.trim() ? contextMessage.trim() : undefined,
        analysisMode: "link",
      };
    } else if (mode === "message") {
      if (!messageInput.trim()) return;
      const extracted = extractUrlsFromText(messageInput);

      // Multi-URL check before sending if user didn't pre-specify a target URL
      if (!messageTargetUrl.trim() && extracted.length > 1) {
        setDetectedUrls(extracted);
        setSelectedMultiUrl(extracted[0]);
        setPendingMessagePayload({
          input: messageInput.trim(),
          messageText: messageInput.trim(),
          analysisMode: "message",
        });
        setShowMultiUrlModal(true);
        return;
      }

      payload = {
        input: messageTargetUrl.trim() || messageInput.trim(),
        messageText: messageInput.trim(),
        targetUrl: messageTargetUrl.trim() || undefined,
        analysisMode: "message",
      };
    } else if (mode === "job") {
      const primaryInput = jobUrl.trim() || jobOfferText.trim() || jobOrg.trim();
      if (!primaryInput) return;

      payload = {
        input: primaryInput,
        messageText: jobOfferText.trim() || undefined,
        targetUrl: jobUrl.trim() || undefined,
        claimedOrganization: jobOrg.trim() || undefined,
        claimedJobRole: jobRole.trim() || undefined,
        officialCareersUrl: jobCareersOverride.trim() || undefined,
        analysisMode: "job",
      };
    } else if (mode === "report") {
      try {
        const parsed = JSON.parse(reportJsonInput);
        if (!parsed.riskOutcome || !parsed.investigationId) {
          throw new Error("Invalid AheadGuard report structure.");
        }
        setResult(parsed);
        saveToLedger(parsed);
        setStatus(`Loaded report · ${parsed.riskOutcome}`);
        return;
      } catch (err) {
        setError(err instanceof Error ? err.message : "Invalid JSON report.");
        return;
      }
    }

    setError(null);
    setResult(null);
    setStreamingUrl(undefined);
    setShowRaw(false);
    setProgressLog([]);
    setLoading(true);
    setStatus("Initiating AheadGuard investigation & scam evaluation…");

    const addLog = (msg: string) => {
      setProgressLog((prev) => [...prev, msg]);
      if (progressBoxRef.current) {
        progressBoxRef.current.scrollTop = progressBoxRef.current.scrollHeight;
      }
    };

    try {
      addLog("Connecting to AheadGuard investigation engine…");

      const response = await fetch("/api/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        let errorMsg = `Server error HTTP ${response.status}`;
        try {
          const errData = await response.json();
          errorMsg = errData.error || errorMsg;
          if (errData.report) {
            setResult(errData.report);
            saveToLedger(errData.report);
          }
        } catch {
          // Non-JSON response
        }
        throw new Error(errorMsg);
      }

      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("text/event-stream") && response.body) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        const handlePacket = (chunk: string) => {
          let eventType = "message";
          const dataLines: string[] = [];

          for (const line of chunk.split(/\r?\n/)) {
            if (line.startsWith("event:")) eventType = line.slice(6).trim();
            if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
          }

          if (!dataLines.length) return;
          const dataRaw = dataLines.join("\n");

          try {
            const parsed = JSON.parse(dataRaw);

            if (eventType === "multiple_urls") {
              // Upstream identified multiple URLs requiring disambiguation
              setDetectedUrls(parsed.extractedUrls || []);
              setSelectedMultiUrl(parsed.extractedUrls?.[0] || "");
              setPendingMessagePayload(payload);
              setShowMultiUrlModal(true);
              setLoading(false);
              return;
            }

            if (eventType === "started") {
              setStatus(parsed.message);
              addLog(`[SESSION] ${parsed.message}`);
            } else if (eventType === "streaming_url") {
              setStreamingUrl(parsed.streamingUrl);
              addLog(`[STREAM] Live sandbox replay URL generated`);
            } else if (eventType === "progress") {
              setStatus(parsed.message);
              addLog(`[PROGRESS] ${parsed.message}`);
            } else if (eventType === "heartbeat") {
              // Heartbeat
            } else if (eventType === "complete") {
              setStatus("Finalizing evidence and claim evaluations…");
              addLog(`[COMPLETED] Sandbox execution finished`);
            } else if (eventType === "report") {
              const rep = (parsed.report || parsed) as InvestigationReport;
              setResult(rep);
              if (rep.replayUrl) setStreamingUrl(rep.replayUrl);
              saveToLedger(rep);
              setStatus(`Investigation completed · ${rep.riskOutcome}`);
              addLog(`[VERDICT] Final risk outcome: ${rep.riskOutcome}`);
              setActiveTab(rep.scamIntelligence ? "intel" : "evidence");
            } else if (eventType === "error") {
              if (parsed.report) {
                setResult(parsed.report);
                saveToLedger(parsed.report);
              }
              throw new Error(parsed.error || parsed.message || "Investigation failed.");
            }
          } catch (err) {
            if (err instanceof Error && err.message !== "Unexpected token") {
              throw err;
            }
          }
        };

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          let splitIdx: number;

          while ((splitIdx = buffer.search(/\r?\n\r?\n/)) >= 0) {
            const chunk = buffer.slice(0, splitIdx);
            const delimiter = buffer.slice(splitIdx).match(/^\r?\n\r?\n/)?.[0] ?? "\n\n";
            buffer = buffer.slice(splitIdx + delimiter.length);

            if (chunk.trim()) {
              handlePacket(chunk);
            }
          }
        }

        if (buffer.trim()) {
          handlePacket(buffer);
          buffer = "";
        }
      } else {
        const data = await response.json();
        if (data.multipleUrls) {
          setDetectedUrls(data.extractedUrls || []);
          setSelectedMultiUrl(data.extractedUrls?.[0] || "");
          setPendingMessagePayload(payload);
          setShowMultiUrlModal(true);
        } else if (data.report) {
          setResult(data.report);
          if (data.report.replayUrl) setStreamingUrl(data.report.replayUrl);
          saveToLedger(data.report);
          setStatus(`Investigation complete · ${data.report.riskOutcome}`);
          setActiveTab(data.report.scamIntelligence ? "intel" : "evidence");
        } else {
          throw new Error(data.error || "No investigation report returned.");
        }
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Unexpected error during investigation.";
      setError(errMsg);
      setStatus("Investigation halted · No safe verdict issued");
      addLog(`[ERROR] ${errMsg}`);
    } finally {
      setLoading(false);
    }
  }

  // Multi-URL selection resolution
  const handleConfirmMultiUrl = () => {
    setShowMultiUrlModal(false);
    if (!pendingMessagePayload) return;

    if (selectedMultiUrl === "__TEXT_ONLY__") {
      runInvestigation({
        ...pendingMessagePayload,
        targetUrl: undefined,
        input: (pendingMessagePayload.messageText as string) || "text://message-analysis",
      });
    } else {
      runInvestigation({
        ...pendingMessagePayload,
        targetUrl: selectedMultiUrl,
        input: selectedMultiUrl,
      });
    }
  };

  // Copy helper
  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus(`Copied ${label}!`);
      setTimeout(() => setCopyStatus(null), 2500);
    } catch {
      setCopyStatus("Failed to copy.");
      setTimeout(() => setCopyStatus(null), 2000);
    }
  };

  const handleDownloadJson = (rep: InvestigationReport) => {
    const shareable = createShareableReport(rep);
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(shareable, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `aheadguard-report-${rep.investigationId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const riskClass =
    result?.riskOutcome === "High risk"
      ? "risk-high"
      : result?.riskOutcome === "Suspicious"
      ? "risk-suspicious"
      : result?.riskOutcome === "Low observed risk"
      ? "risk-low"
      : "risk-unknown";

  const intel = result?.scamIntelligence;
  const filteredClaims = (intel?.claims || []).filter((c) => (claimFilter === "All" ? true : c.evaluation === claimFilter));

  return (
    <main className="app-shell">
      {/* Top Bar */}
      <header className="topbar">
        <a className="brand" href="#top" aria-label="AheadGuard AI home">
          <span className="brand-mark">
            <ShieldIcon />
          </span>
          <span className="brand-text">
            <span className="brand-title">
              AheadGuard <span className="brand-accent">AI</span>
            </span>
            <span className="brand-subtitle">DIGITAL TRUST, SCAM & SAFETY INTELLIGENCE</span>
          </span>
        </a>
        <div className="topbar-right">
          <span className="engine-status-badge" role="status" aria-live="polite">
            <span className="status-dot" /> Evidence Engine Active
          </span>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="eyebrow-line" /> EVIDENCE-DRIVEN DIGITAL TRUST
          </div>
          <h1>
            Your AI checks first.
            <br />
            <span className="gradient-text">You act with confidence.</span>
          </h1>
          <p>
            AheadGuard investigates suspicious messages, internship & job offers, payment demands, and unexpected links
            before you commit. It verifies identities against official sources, isolates malicious traps in a sandbox,
            and provides grounded, claim-by-claim clarity.
          </p>
          <div className="feature-pill-row">
            <span className="feature-pill">
              <Icon name="shield" /> Claim Ledger
            </span>
            <span className="feature-pill">
              <Icon name="search" /> Identity Match
            </span>
            <span className="feature-pill">
              <Icon name="radar" /> Isolated Sandbox
            </span>
            <span className="feature-pill">
              <Icon name="lock" /> Privacy Redaction
            </span>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="radar-ring ring-1" />
          <div className="radar-ring ring-2" />
          <div className="radar-center-shield">
            <ShieldIcon />
          </div>
          <div className="radar-caption">
            <span className="pulse-label">
              <span className="status-dot blinking" /> READY TO VERIFY
            </span>
            <span>ZERO SENSITIVE DATA LOGGING</span>
          </div>
        </div>
      </section>

      {/* Offline Demonstration Scenarios */}
      <section className="demo-scenarios-strip" aria-label="Interactive Demo Scenarios">
        <div className="demo-scenarios-header">
          <div className="demo-scenarios-title">
            <Icon name="sparkles" /> INTERACTIVE OFFLINE DEMO SCENARIOS
          </div>
          <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
            Instant offline evaluation · Zero TinyFish API calls · Ground-truth verified
          </span>
        </div>
        <div className="demo-scenarios-grid">
          {DEMO_SCENARIOS.map((scen) => (
            <button
              key={scen.id}
              type="button"
              className={`demo-scenario-card ${activeDemoScenarioId === scen.id ? "active" : ""}`}
              onClick={() => handleSelectDemoScenario(scen.id)}
            >
              <div className="demo-card-head">
                <span className="demo-card-title">{scen.name}</span>
                <span
                  className={`intel-badge ${
                    scen.category === "verified"
                      ? "badge-match"
                      : scen.category === "suspicious"
                      ? "badge-mismatch"
                      : "badge-unverified"
                  }`}
                  style={{ fontSize: "10px", padding: "1px 6px" }}
                >
                  {scen.badge}
                </span>
              </div>
              <p className="demo-card-summary">{scen.summary}</p>
              <div className="demo-card-meta">
                <span>{scen.targetOrg}</span>
              </div>
            </button>
          ))}
        </div>
      </section>

      {/* Main Workspace Grid */}
      <section className="workspace-grid">
        {/* Panel 1: Input & Mode Selection */}
        <div className="panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">01 / SUBMIT FOR VERIFICATION</span>
              <h2>Choose Investigation Mode</h2>
            </div>
            <span className="panel-icon-badge">
              <Icon name="link" />
            </span>
          </div>

          {/* Mode Selector Tabs */}
          <nav className="mode-selector-nav" aria-label="Investigation Mode">
            <button
              className={`mode-tab-btn ${mode === "link" ? "active" : ""}`}
              onClick={() => setMode("link")}
              disabled={loading}
              type="button"
            >
              <Icon name="link" />
              <span>Check a Link</span>
            </button>
            <button
              className={`mode-tab-btn ${mode === "message" ? "active" : ""}`}
              onClick={() => setMode("message")}
              disabled={loading}
              type="button"
            >
              <Icon name="file-text" />
              <span>Analyze a Message</span>
            </button>
            <button
              className={`mode-tab-btn ${mode === "job" ? "active" : ""}`}
              onClick={() => setMode("job")}
              disabled={loading}
              type="button"
            >
              <Icon name="shield-check" />
              <span>Verify Job Offer</span>
            </button>
            <button
              className={`mode-tab-btn ${mode === "report" ? "active" : ""}`}
              onClick={() => setMode("report")}
              disabled={loading}
              type="button"
            >
              <Icon name="braces" />
              <span>Review Report</span>
            </button>
          </nav>

          {/* MODE 1: Check a Link */}
          {mode === "link" && (
            <div className="mode-form-container">
              <p className="panel-description">
                Submit an unknown or suspicious URL. AheadGuard inspects redirect chains, credential/payment forms,
                and lookalike deception in a constrained read-only sandbox.
              </p>

              <div className="input-label-row">
                <label className="input-label" htmlFor="link-target-input">
                  Target Destination URL
                </label>
                <span className="char-count">{linkInput.length}/2000</span>
              </div>

              <div className="input-textarea-wrapper">
                <input
                  id="link-target-input"
                  className="input-text-input"
                  style={{ width: "100%", fontSize: "14px", padding: "12px 14px" }}
                  value={linkInput}
                  onChange={(e) => setLinkInput(e.target.value)}
                  placeholder="https://example.com/login"
                  disabled={loading}
                />
              </div>

              {/* Optional context message toggle */}
              <div style={{ marginTop: "12px" }}>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ padding: "6px 10px", fontSize: "11px" }}
                  onClick={() => setShowContextMessage(!showContextMessage)}
                >
                  <Icon name="file-text" />
                  <span>{showContextMessage ? "Hide Message Context" : "+ Add Message Context (Optional)"}</span>
                </button>
              </div>

              {showContextMessage && (
                <div style={{ marginTop: "10px" }}>
                  <label className="input-label" htmlFor="context-message-input">
                    Accompanying Message or Email Text
                  </label>
                  <textarea
                    id="context-message-input"
                    className="input-textarea"
                    style={{ minHeight: "80px" }}
                    value={contextMessage}
                    onChange={(e) => setContextMessage(e.target.value)}
                    placeholder="Paste the SMS, WhatsApp, or email message that accompanied this link…"
                    disabled={loading}
                  />
                </div>
              )}

              {/* Test scenarios */}
              <div className="scenario-section">
                <span className="scenario-title">TEST SCENARIOS</span>
                <div className="scenario-chips">
                  {LINK_EXAMPLES.map((ex) => (
                    <button
                      className="scenario-btn"
                      key={ex.label}
                      onClick={() => setLinkInput(ex.value)}
                      disabled={loading}
                      type="button"
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MODE 2: Analyze a Message */}
          {mode === "message" && (
            <div className="mode-form-container">
              <p className="panel-description">
                Paste an unexpected WhatsApp, Telegram, SMS, or email message. AheadGuard automatically redacts personal
                details, extracts links and claims, detects recruitment fees, and evaluates risk.
              </p>

              <div className="input-label-row">
                <label className="input-label" htmlFor="message-text-input">
                  Suspicious Message Text
                </label>
                <span className="char-count">{messageInput.length}/4000</span>
              </div>

              <div className="input-textarea-wrapper">
                <textarea
                  id="message-text-input"
                  className="input-textarea"
                  style={{ minHeight: "130px" }}
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  placeholder="Congratulations! You have been selected for a part-time job. Pay $50 registration fee via UPI to..."
                  maxLength={4000}
                  disabled={loading}
                />
              </div>

              <div className="input-meta-bar">
                <span>Client-side PII redaction active: Phone numbers, emails, and IDs are masked.</span>
              </div>

              <div style={{ marginTop: "12px" }}>
                <label className="input-label" htmlFor="message-explicit-url">
                  Explicit Target URL (Optional override)
                </label>
                <input
                  id="message-explicit-url"
                  className="input-text-input"
                  style={{ width: "100%" }}
                  value={messageTargetUrl}
                  onChange={(e) => setMessageTargetUrl(e.target.value)}
                  placeholder="https://... (Leave empty to auto-extract from message)"
                  disabled={loading}
                />
              </div>

              {/* Message scenario chips */}
              <div className="scenario-section">
                <span className="scenario-title">SAMPLE SCAM PATTERNS</span>
                <div className="scenario-chips">
                  {MESSAGE_EXAMPLES.map((ex) => (
                    <button
                      className="scenario-btn"
                      key={ex.label}
                      onClick={() => {
                        setMessageInput(ex.value);
                        setMessageTargetUrl("");
                      }}
                      disabled={loading}
                      type="button"
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MODE 3: Verify a Job Offer */}
          {mode === "job" && (
            <div className="mode-form-container">
              <p className="panel-description">
                Verify an internship or employment offer. Compare the claimed employer against verified corporate
                registries, cross-reference application portals, and detect illegal recruitment fees.
              </p>

              <div className="job-inputs-grid">
                <div className="input-field-group">
                  <label className="input-label" htmlFor="job-org-input">
                    Claimed Employer / Company *
                  </label>
                  <input
                    id="job-org-input"
                    className="input-text-input"
                    value={jobOrg}
                    onChange={(e) => setJobOrg(e.target.value)}
                    placeholder="e.g. Google, Amazon, Infosys"
                    disabled={loading}
                  />
                </div>

                <div className="input-field-group">
                  <label className="input-label" htmlFor="job-role-input">
                    Job / Internship Title
                  </label>
                  <input
                    id="job-role-input"
                    className="input-text-input"
                    value={jobRole}
                    onChange={(e) => setJobRole(e.target.value)}
                    placeholder="e.g. Software Engineer Intern"
                    disabled={loading}
                  />
                </div>

                <div className="input-field-group">
                  <label className="input-label" htmlFor="job-comp-input">
                    Stated Compensation / Stipend
                  </label>
                  <input
                    id="job-comp-input"
                    className="input-text-input"
                    value={jobComp}
                    onChange={(e) => setJobComp(e.target.value)}
                    placeholder="e.g. $45/hr or ₹50,000/mo"
                    disabled={loading}
                  />
                </div>

                <div className="input-field-group">
                  <label className="input-label" htmlFor="job-recruiter-input">
                    Recruiter Name / Handle
                  </label>
                  <input
                    id="job-recruiter-input"
                    className="input-text-input"
                    value={jobRecruiter}
                    onChange={(e) => setJobRecruiter(e.target.value)}
                    placeholder="e.g. HR Team, @recruiter_bot"
                    disabled={loading}
                  />
                </div>

                <div className="input-field-group full-width">
                  <label className="input-label" htmlFor="job-url-input">
                    Application or Offer Link
                  </label>
                  <input
                    id="job-url-input"
                    className="input-text-input"
                    value={jobUrl}
                    onChange={(e) => setJobUrl(e.target.value)}
                    placeholder="https://..."
                    disabled={loading}
                  />
                </div>

                <div className="input-field-group full-width">
                  <label className="input-label" htmlFor="job-careers-override">
                    Official Careers Site URL (Optional override)
                  </label>
                  <input
                    id="job-careers-override"
                    className="input-text-input"
                    value={jobCareersOverride}
                    onChange={(e) => setJobCareersOverride(e.target.value)}
                    placeholder="https://careers.company.com (if known)"
                    disabled={loading}
                  />
                </div>

                <div className="input-field-group full-width">
                  <label className="input-label" htmlFor="job-offer-text">
                    Offer Letter Excerpt or Message
                  </label>
                  <textarea
                    id="job-offer-text"
                    className="input-textarea"
                    style={{ minHeight: "80px" }}
                    value={jobOfferText}
                    onChange={(e) => setJobOfferText(e.target.value)}
                    placeholder="Paste the offer letter text, email body, or WhatsApp hiring instructions…"
                    disabled={loading}
                  />
                </div>
              </div>

              {/* Sample job presets */}
              <div className="scenario-section">
                <span className="scenario-title">VERIFICATION PRESETS</span>
                <div className="scenario-chips">
                  {JOB_EXAMPLES.map((ex) => (
                    <button
                      className="scenario-btn"
                      key={ex.label}
                      onClick={() => {
                        setJobOrg(ex.org);
                        setJobRole(ex.role);
                        setJobComp(ex.comp);
                        setJobRecruiter(ex.recruiter);
                        setJobUrl(ex.url);
                        setJobCareersOverride(ex.careersUrl);
                        setJobOfferText(ex.notes || "");
                      }}
                      disabled={loading}
                      type="button"
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MODE 4: Review a Report */}
          {mode === "report" && (
            <div className="mode-form-container">
              <p className="panel-description">
                Paste an exported AheadGuard report JSON to view the verified claims, sandbox evidence, and independent
                routes locally without sending any data over the network.
              </p>

              <div className="input-label-row">
                <label className="input-label" htmlFor="report-json-input">
                  AheadGuard Report JSON
                </label>
                <span className="char-count">{reportJsonInput.length} chars</span>
              </div>

              <div className="input-textarea-wrapper">
                <textarea
                  id="report-json-input"
                  className="input-textarea"
                  style={{ minHeight: "160px", fontFamily: "var(--font-mono)", fontSize: "12px" }}
                  value={reportJsonInput}
                  onChange={(e) => setReportJsonInput(e.target.value)}
                  placeholder='{"investigationId": "inv_...", "riskOutcome": "High risk", ...}'
                  disabled={loading}
                />
              </div>
            </div>
          )}

          {/* Action button */}
          <button
            className="btn-primary"
            style={{ marginTop: "16px" }}
            onClick={() => runInvestigation()}
            disabled={
              loading ||
              (mode === "link" && linkInput.trim().length < 4) ||
              (mode === "message" && messageInput.trim().length < 5) ||
              (mode === "job" && !jobOrg.trim() && !jobUrl.trim() && !jobOfferText.trim()) ||
              (mode === "report" && reportJsonInput.trim().length < 10)
            }
            type="button"
          >
            {loading ? <Spinner /> : <Icon name="scan-search" />}
            <span>
              {loading
                ? "Analyzing & Investigating…"
                : mode === "report"
                ? "Load & Render Report"
                : mode === "job"
                ? "Verify Job Offer & Claims"
                : mode === "message"
                ? "Analyze Message & Links"
                : "Investigate Destination"}
            </span>
            <Icon name="arrow-up-right" />
          </button>

          <div className="boundary-notice">
            <Icon name="lock" />
            <span>
              <strong>Read-only boundary enforced:</strong> The investigator will not log in, submit forms, pay fees, or
              disclose credentials.
            </span>
          </div>
        </div>

        {/* Panel 2: Investigation & Scam Intelligence Findings */}
        <div className="panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">02 / EVIDENCE & VERDICT</span>
              <h2>Digital Trust Report</h2>
            </div>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              {result && (
                <button
                  className="btn-secondary"
                  style={{ padding: "6px 12px", fontSize: "12px" }}
                  onClick={() => setShowShareModal(true)}
                  type="button"
                >
                  <Icon name="file-text" />
                  <span>Share / Export</span>
                </button>
              )}
              <span className="panel-icon-badge">
                <Icon name="activity" />
              </span>
            </div>
          </div>

          <div className="status-bar" role="status" aria-live="polite">
            <span className={loading ? "status-dot blinking" : "status-dot"} />
            <span>{status}</span>
            <span className="status-pill-end">{loading ? "STREAMING" : "VERIFIED"}</span>
          </div>

          {/* Real-Time Streaming Logs */}
          {loading && progressLog.length > 0 && (
            <div className="terminal-stream-box" ref={progressBoxRef} aria-label="Investigation progress log">
              {progressLog.map((log, idx) => (
                <div key={idx} className="terminal-line">
                  <span className="t-dot" />
                  <span>{log}</span>
                </div>
              ))}
            </div>
          )}

          {/* Error Alert */}
          {error && (
            <div className="alert-card-danger" role="alert">
              <div className="alert-head">
                <Icon name="alert-triangle" />
                <span>Investigation Alert</span>
              </div>
              <p>{error}</p>
              {error.includes("TINYFISH_API_KEY") && (
                <code>Add TINYFISH_API_KEY=your_key to .env.local and restart your server.</code>
              )}
            </div>
          )}

          {/* Empty State */}
          {!result && !error && (
            <div className="empty-hud">
              <div className="empty-hud-icon">
                <Icon name="radar" />
              </div>
              <h3>{loading ? "Analyzing claims & inspecting destination" : "Investigation has not run yet"}</h3>
              <p>
                {loading
                  ? "AheadGuard is evaluating claims, redacting sensitive data, and probing destinations in an isolated sandbox. Please wait…"
                  : "Submit a link, paste a suspicious message, or verify a job offer. AheadGuard will ground every finding in observable evidence."}
              </p>
              <div className="step-roadmap">
                <div className={`roadmap-item ${loading ? "active" : ""}`}>
                  <span className="item-num">01</span> Redact PII & extract claim records
                </div>
                <div className={`roadmap-item ${loading ? "active" : ""}`}>
                  <span className="item-num">02</span> Verify company identity against official registries
                </div>
                <div className={`roadmap-item ${result ? "active" : ""}`}>
                  <span className="item-num">03</span> Synthesize claims into Supported, Contradicted, or Unverified
                </div>
              </div>
            </div>
          )}

          {/* Active Result View */}
          {result && (
            <div className="assessment-container">
              {/* Sticky Demo Banner if viewing offline demo data */}
              {isDemoReport(result) && (
                <div className="demo-banner-sticky" role="region" aria-label="Demo mode notice">
                  <div className="demo-banner-left">
                    <span className="demo-badge-pill">⚠️ DEMO DATA — NOT A LIVE INVESTIGATION</span>
                    <span className="demo-banner-text">
                      Viewing illustrative demonstration data ({result.claimedOrganization || result.observedDestination.submittedHost}). No live network request or crawler inspection occurred.
                    </span>
                  </div>
                  <button type="button" className="demo-exit-btn" onClick={handleExitDemoMode}>
                    Exit Demo Mode
                  </button>
                </div>
              )}

              {/* Risk Banner */}
              <div className={`risk-banner ${riskClass}`} role="region" aria-label="Risk outcome summary">
                <div className="risk-banner-icon">
                  <Icon
                    name={
                      result.riskOutcome === "High risk" || result.riskOutcome === "Suspicious"
                        ? "shield-alert"
                        : result.riskOutcome === "Low observed risk"
                        ? "shield-check"
                        : "circle-help"
                    }
                  />
                </div>
                <div className="risk-banner-content">
                  <div className="risk-header-row">
                    <span className="risk-overline">DETERMINISTIC VERDICT</span>
                    <span className="metric-pill">
                      Likelihood: {result.threatLikelihood} · Impact: {result.consequenceImpact}
                    </span>
                  </div>
                  <h3 className="risk-banner-title">{result.riskOutcome}</h3>
                  <p className="risk-banner-desc">{result.outcomeReason}</p>

                  {/* Low Risk Disclaimer */}
                  {result.riskOutcome === "Low observed risk" && (
                    <div className="safety-disclaimer-callout">
                      <Icon name="info" />
                      <span>
                        <strong>Notice:</strong> Low observed risk indicates no active warning signals were observed during
                        this probe. It is not an absolute guarantee of future safety.
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Status Badges: Company Identity & Job Verification */}
              {intel && (
                <div className="identity-badge-row">
                  {/* Company Identity Status */}
                  <span
                    className={`intel-badge ${
                      intel.companyIdentity.status === "Official domain match" ||
                      intel.companyIdentity.status === "Affiliated domain observed"
                        ? "badge-match"
                        : intel.companyIdentity.status === "Identity mismatch"
                        ? "badge-mismatch"
                        : intel.companyIdentity.status === "Third-party platform"
                        ? "badge-platform"
                        : "badge-unverified"
                    }`}
                  >
                    <Icon
                      name={
                        intel.companyIdentity.status === "Official domain match"
                          ? "shield-check"
                          : intel.companyIdentity.status === "Identity mismatch"
                          ? "shield-alert"
                          : "info"
                      }
                    />
                    Company: {intel.companyIdentity.status}
                  </span>

                  {/* Job Verification Status */}
                  {intel.jobVerification && (
                    <span
                      className={`intel-badge ${
                        intel.jobVerification.status === "Listing matched"
                          ? "badge-match"
                          : intel.jobVerification.status === "Listing contradicted"
                          ? "badge-mismatch"
                          : intel.jobVerification.status === "Listing not found — unverified"
                          ? "badge-unverified"
                          : "badge-neutral"
                      }`}
                    >
                      <Icon
                        name={
                          intel.jobVerification.status === "Listing matched"
                            ? "check-circle"
                            : intel.jobVerification.status === "Listing contradicted"
                            ? "alert-circle"
                            : "circle-help"
                        }
                      />
                      Job: {intel.jobVerification.status}
                    </span>
                  )}
                </div>
              )}

              {/* Recruitment Fee Alert Card */}
              {intel?.recruitmentFeeWarning?.detected && (
                <div className="fee-warning-banner" role="alert">
                  <div className="fee-warning-head">
                    <span className="fee-warning-title">
                      <Icon name="alert-triangle" /> RECRUITMENT FEE DEMAND DETECTED
                    </span>
                    <span className="intel-badge badge-mismatch">CRITICAL RISK</span>
                  </div>
                  <div className="fee-quote-box">&ldquo;{intel.recruitmentFeeWarning.quotedText}&rdquo;</div>
                  <p className="fee-explanation-text">
                    {intel.recruitmentFeeWarning.explanation} Legitimate corporate employers never demand registration fees,
                    caution deposits, or equipment charges from candidates.
                  </p>
                </div>
              )}

              {/* Evidence Coverage & Integrity Card */}
              <EvidenceCoverageCard report={result} />

              {/* Action Preview & Safe Action Planner */}
              <div className="action-preview-card">
                <div className="action-preview-head">
                  <span className="action-preview-title">
                    <Icon name="eye" /> Safe Action Planner: Impact & Next Steps
                  </span>
                  <span className="action-badge">{result.actionPreview.proposedAction}</span>
                </div>
                <p className="action-consequence-text">{result.actionPreview.consequenceIfProceed}</p>

                {/* Grounded Safety Checklists & Traps Gate */}
                <div className="action-checklist">
                  {intel?.recruitmentFeeWarning?.detected && (
                    <div className="checklist-item critical">
                      <Icon name="alert-triangle" />
                      <span>
                        <strong>CRITICAL SAFETY BLOCK:</strong> Do not transfer the requested fee or security deposit. Legitimate corporate recruitment never involves candidate payments.
                      </span>
                    </div>
                  )}

                  {intel?.companyIdentity?.status === "Identity mismatch" && (
                    <div className="checklist-item critical">
                      <Icon name="shield-alert" />
                      <span>
                        <strong>LOOKALIKE CHANNEL CAUTION:</strong> The observed domain does not belong to the claimed organization. Do not proceed via recruiter links; independently confirm openings on the official corporate careers portal.
                      </span>
                    </div>
                  )}

                  {intel?.sensitiveDataRequests && intel.sensitiveDataRequests.length > 0 && (
                    <div className="checklist-item caution">
                      <Icon name="lock" />
                      <span>
                        <strong>CREDENTIAL SHIELD:</strong> Do not upload passport scans, government IDs, OTPs, or banking verification screenshots to this destination.
                      </span>
                    </div>
                  )}

                  <div className="checklist-item">
                    <Icon name="check-circle" />
                    <span>
                      <strong>Safe Recommendation:</strong> {result.recommendedAction}
                    </span>
                  </div>
                </div>

                {result.actionPreview.riskFactors.length > 0 && (
                  <ul className="risk-factor-list" style={{ marginTop: "12px" }}>
                    {result.actionPreview.riskFactors.map((factor, i) => (
                      <li key={i}>{factor}</li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Destination & Host Meta */}
              <div className="destination-meta-card">
                <div>
                  <span className="meta-field-label">SUBMITTED HOST</span>
                  <div className="meta-field-value">{result.observedDestination.submittedHost}</div>
                </div>

                {result.observedDestination.destinationChanged && (
                  <div className="redirect-alert-row">
                    <Icon name="alert-circle" />
                    <span>
                      Redirect detected: Final host resolved to{" "}
                      <strong>{result.observedDestination.finalHost || "external domain"}</strong>
                    </span>
                  </div>
                )}

                {result.observedDestination.finalUrl && (
                  <div>
                    <span className="meta-field-label">REPORTED FINAL DESTINATION</span>
                    <a
                      href={result.observedDestination.finalUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="meta-field-value"
                      style={{ color: "var(--cyan)", display: "inline-flex", alignItems: "center", gap: "6px" }}
                    >
                      {result.observedDestination.finalUrl} <Icon name="external-link" />
                    </a>
                  </div>
                )}

                {result.claimedOrganization && (
                  <div>
                    <span className="meta-field-label">CLAIMED IDENTITY</span>
                    <div className="meta-field-value">{result.claimedOrganization}</div>
                  </div>
                )}
              </div>

              {/* Navigation Tabs */}
              <div className="tab-navigation" role="tablist">
                <button
                  className={`tab-btn ${activeTab === "trustgap" ? "active" : ""}`}
                  onClick={() => setActiveTab("trustgap")}
                  role="tab"
                  aria-selected={activeTab === "trustgap"}
                  type="button"
                >
                  <Icon name="map" />
                  <span>Trust Gap Map</span>
                </button>
                {intel && (
                  <>
                    <button
                      className={`tab-btn ${activeTab === "intel" ? "active" : ""}`}
                      onClick={() => setActiveTab("intel")}
                      role="tab"
                      aria-selected={activeTab === "intel"}
                      type="button"
                    >
                      Scam Intelligence
                    </button>
                    <button
                      className={`tab-btn ${activeTab === "claims" ? "active" : ""}`}
                      onClick={() => setActiveTab("claims")}
                      role="tab"
                      aria-selected={activeTab === "claims"}
                      type="button"
                    >
                      Claims Ledger ({intel.claims.length})
                    </button>
                    <button
                      className={`tab-btn ${activeTab === "routes" ? "active" : ""}`}
                      onClick={() => setActiveTab("routes")}
                      role="tab"
                      aria-selected={activeTab === "routes"}
                      type="button"
                    >
                      Verified Routes ({intel.independentVerificationRoutes.length})
                    </button>
                  </>
                )}
                <button
                  className={`tab-btn ${activeTab === "evidence" ? "active" : ""}`}
                  onClick={() => setActiveTab("evidence")}
                  role="tab"
                  aria-selected={activeTab === "evidence"}
                  type="button"
                >
                  Evidence & Findings ({result.evidenceItems.length})
                </button>
                <button
                  className={`tab-btn ${activeTab === "facts" ? "active" : ""}`}
                  onClick={() => setActiveTab("facts")}
                  role="tab"
                  aria-selected={activeTab === "facts"}
                  type="button"
                >
                  Observed Facts
                </button>
                <button
                  className={`tab-btn ${activeTab === "checks" ? "active" : ""}`}
                  onClick={() => setActiveTab("checks")}
                  role="tab"
                  aria-selected={activeTab === "checks"}
                  type="button"
                >
                  Checks ({result.checksPerformed.length})
                </button>
              </div>

              {/* TAB: Trust Gap Map */}
              {activeTab === "trustgap" && (
                <div role="tabpanel">
                  <TrustGapMap report={result} />
                </div>
              )}

              {/* TAB: Scam Intelligence Overview */}
              {activeTab === "intel" && intel && (
                <div role="tabpanel">
                  {/* Company Verification Breakdown */}
                  <div className="intel-section">
                    <span className="intel-section-title">
                      <Icon name="search-check" /> Organization Identity Verification
                    </span>
                    <p style={{ margin: "0 0 10px", fontSize: "13px", color: "var(--text-secondary)" }}>
                      {intel.companyIdentity.explanation}
                    </p>
                    {intel.companyIdentity.officialDomains.length > 0 && (
                      <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        Approved corporate domains:{" "}
                        <code style={{ color: "var(--cyan)" }}>
                          {intel.companyIdentity.officialDomains.join(", ")}
                        </code>
                      </div>
                    )}
                  </div>

                  {/* Specific Vacancy Verification Breakdown */}
                  {intel.jobVerification && (
                    <div className="intel-section">
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                        <span className="intel-section-title" style={{ margin: 0 }}>
                          <Icon name="briefcase" /> Specific Vacancy Verification
                        </span>
                        <span
                          className={`intel-badge ${
                            intel.jobVerification.status === "Listing matched"
                              ? "badge-match"
                              : intel.jobVerification.status === "Listing contradicted"
                              ? "badge-mismatch"
                              : intel.jobVerification.status === "Listing not found — unverified"
                              ? "badge-unverified"
                              : "badge-neutral"
                          }`}
                        >
                          {intel.jobVerification.status}
                        </span>
                      </div>
                      <p style={{ margin: "0 0 8px", fontSize: "13px", color: "var(--text-secondary)" }}>
                        {intel.jobVerification.explanation}
                      </p>
                      {intel.jobVerification.claimedRole && (
                        <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "4px" }}>
                          Advertised Role: <strong style={{ color: "var(--text-primary)" }}>{intel.jobVerification.claimedRole}</strong>
                          {intel.jobVerification.claimedEmployer ? ` at ${intel.jobVerification.claimedEmployer}` : ""}
                        </div>
                      )}
                      {intel.jobVerification.limitations && (
                        <div style={{ fontSize: "11px", color: "var(--text-dim)", fontStyle: "italic", marginTop: "6px" }}>
                          Verification Scope: {intel.jobVerification.limitations}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Payment Risks */}
                  {intel.paymentRisks.length > 0 && (
                    <div className="intel-section">
                      <span className="intel-section-title">
                        <Icon name="alert-triangle" /> Payment & Financial Risks ({intel.paymentRisks.length})
                      </span>
                      <div className="risk-items-grid">
                        {intel.paymentRisks.map((pr) => (
                          <div key={pr.id} className="risk-item-card">
                            <div className="risk-item-header">
                              <span className="risk-item-tag">{pr.paymentType.replace("_", " ")}</span>
                              {pr.claimedRecipient && (
                                <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                                  Recipient: {pr.claimedRecipient}
                                </span>
                              )}
                            </div>
                            <div className="risk-item-quote">&ldquo;{pr.quotedText}&rdquo;</div>
                            <p className="risk-item-detail">{pr.cautionReason}</p>
                            <div style={{ marginTop: "6px", fontSize: "11px", color: "var(--cyan)" }}>
                              Advice: {pr.recommendedVerificationStep}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Sensitive Data Requests */}
                  {intel.sensitiveDataRequests.length > 0 && (
                    <div className="intel-section">
                      <span className="intel-section-title">
                        <Icon name="lock" /> Sensitive Data Requests ({intel.sensitiveDataRequests.length})
                      </span>
                      <div className="risk-items-grid">
                        {intel.sensitiveDataRequests.map((s) => (
                          <div key={s.id} className="risk-item-card">
                            <div className="risk-item-header">
                              <span className="risk-item-tag">{s.dataCategory.replace("_", " ")}</span>
                              <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>{s.source.replace(/_/g, " ")}</span>
                            </div>
                            {s.quotedText && <div className="risk-item-quote">&ldquo;{s.quotedText}&rdquo;</div>}
                            <p className="risk-item-detail">{s.riskExplanation}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Redacted Message Excerpt */}
                  {intel.messageExcerpt && (
                    <div className="intel-section">
                      <span className="intel-section-title">
                        <Icon name="file-text" /> Sanitized Message Excerpt
                      </span>
                      <pre className="share-preview-box" style={{ maxHeight: "160px" }}>
                        {intel.messageExcerpt}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* TAB: Claims Ledger */}
              {activeTab === "claims" && intel && (
                <div role="tabpanel">
                  <div className="claims-ledger-header">
                    <span className="scenario-title" style={{ margin: 0 }}>
                      CLAIM-BY-CLAIM EVIDENCE MATRIX
                    </span>
                    <div className="claims-filter-group">
                      {(["All", "Supported", "Contradicted", "Unverified"] as const).map((fil) => (
                        <button
                          key={fil}
                          className={`claims-filter-tab ${claimFilter === fil ? "active" : ""}`}
                          onClick={() => setClaimFilter(fil)}
                          type="button"
                        >
                          {fil}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="claims-card-list">
                    {filteredClaims.map((claim) => (
                      <div
                        key={claim.id}
                        className={`claim-record-card claim-${claim.evaluation.toLowerCase()}`}
                      >
                        <div className="claim-top-row">
                          <span className="claim-cat-tag">{claim.category.replace("_", " ")}</span>
                          <span className={`claim-eval-badge ${claim.evaluation.toLowerCase()}`}>
                            {claim.evaluation}
                          </span>
                        </div>
                        <h4 className="claim-statement">{claim.claimText}</h4>
                        <p className="claim-explanation">{claim.explanation}</p>
                        <div className="claim-source-footer">
                          <span>Provenance: {claim.provenance.replace("_", " ")}</span>
                          {claim.sourceUrl && (
                            <a
                              href={claim.sourceUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="claim-source-link"
                            >
                              <span>{claim.sourceType?.replace(/_/g, " ") || "source"}</span>
                              <Icon name="external-link" />
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                    {filteredClaims.length === 0 && (
                      <p style={{ color: "var(--text-muted)", fontSize: "12px", padding: "16px 0" }}>
                        No claims in this category.
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* TAB: Independent Verification Routes */}
              {activeTab === "routes" && intel && (
                <div role="tabpanel">
                  <div className="routes-warning-box">
                    <Icon name="alert-triangle" />
                    <div>
                      <strong>CRITICAL CYBERSECURITY RULE:</strong>
                      <div style={{ marginTop: "2px" }}>
                        Never verify an offer or security alert using links, phone numbers, or QR codes sent inside the
                        suspicious message itself. Always use independent official channels below.
                      </div>
                    </div>
                  </div>

                  <div className="routes-grid">
                    {intel.independentVerificationRoutes.map((route, i) => (
                      <div key={i} className="route-card">
                        <div className="route-header">
                          <span className="route-title">{route.title}</span>
                          <span className="intel-badge badge-match">
                            {route.isIndependentlyEstablished ? "VERIFIED DIRECT" : "INDEPENDENT SEARCH"}
                          </span>
                        </div>
                        <p className="route-desc">{route.relevanceExplanation}</p>
                        {route.url && (
                          <a
                            href={route.url}
                            target="_blank"
                            rel="noreferrer"
                            className="route-link-btn"
                          >
                            <span>Open {route.title}</span>
                            <Icon name="external-link" />
                          </a>
                        )}
                        <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "4px" }}>
                          Limitations: {route.limitations}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB: Evidence & Findings */}
              {activeTab === "evidence" && (
                <div className="findings-container" role="tabpanel">
                  {result.evidenceItems.map((item, idx) => (
                    <div className="finding-card" key={idx}>
                      <span
                        className={`finding-icon-wrap ${
                          item.kind === "warning" ? "warning" : item.kind === "positive" ? "positive" : "neutral"
                        }`}
                      >
                        <Icon
                          name={
                            item.kind === "warning"
                              ? "alert-circle"
                              : item.kind === "positive"
                              ? "check-circle"
                              : "info"
                          }
                        />
                      </span>
                      <div className="finding-body">
                        <div className="finding-header-line">
                          <span className="finding-title">{item.label}</span>
                          <span className="provenance-pill">{item.provenance.replace("_", " ")}</span>
                        </div>
                        <p className="finding-detail">{item.detail}</p>
                      </div>
                    </div>
                  ))}
                  {result.evidenceItems.length === 0 && (
                    <p style={{ color: "var(--text-muted)", fontSize: "12px", padding: "12px 0" }}>
                      No specific warning items observed.
                    </p>
                  )}
                </div>
              )}

              {/* TAB: Observed Facts */}
              {activeTab === "facts" && (
                <div role="tabpanel">
                  <span className="scenario-title">DIRECT OBSERVATIONS (FACTS)</span>
                  <div className="facts-grid-layout">
                    <div className="fact-card">
                      <span className="fact-card-label">PAGE TITLE</span>
                      <span className="fact-card-val">{result.observedFacts.pageTitle || "None detected"}</span>
                    </div>
                    <div className="fact-card">
                      <span className="fact-card-label">CREDENTIAL PROMPT</span>
                      <span className="fact-card-val">
                        {result.observedFacts.credentialOrPaymentRequest ? "YES (Observed)" : "No"}
                      </span>
                    </div>
                    <div className="fact-card">
                      <span className="fact-card-label">PASSWORD FIELD</span>
                      <span className="fact-card-val">
                        {result.observedFacts.hasPasswordField ? "YES (Detected)" : "No"}
                      </span>
                    </div>
                    <div className="fact-card">
                      <span className="fact-card-label">PAYMENT INPUT</span>
                      <span className="fact-card-val">
                        {result.observedFacts.hasPaymentField ? "YES (Detected)" : "No"}
                      </span>
                    </div>
                    <div className="fact-card">
                      <span className="fact-card-label">DOWNLOAD PROMPT</span>
                      <span className="fact-card-val">
                        {result.observedFacts.downloadOrPermissionRequest ? "YES (Detected)" : "No"}
                      </span>
                    </div>
                    <div className="fact-card">
                      <span className="fact-card-label">ENCRYPTED HTTPS</span>
                      <span className="fact-card-val">
                        {!result.observedFacts.isHttp ? "Yes (Valid Scheme)" : "NO (Insecure HTTP)"}
                      </span>
                    </div>
                  </div>

                  {result.modelInterpretations.length > 0 && (
                    <div className="interpretations-section">
                      <span className="scenario-title">MODEL INTERPRETATIONS (SEPARATED)</span>
                      {result.modelInterpretations.map((interp, i) => (
                        <div key={i} className="interpretation-item">
                          <div className="interp-head">
                            <span>{interp.aspect}</span>
                            <span className="interp-conf">Confidence: {interp.confidence}</span>
                          </div>
                          <p className="interp-text">{interp.interpretation}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB: Checks Performed */}
              {activeTab === "checks" && (
                <div role="tabpanel">
                  <ul className="checks-checklist">
                    {result.checksPerformed.map((chk, i) => (
                      <li key={i} className="check-item">
                        <Icon name="check" />
                        <div>
                          <span className="check-name">{chk.name}:</span>
                          <span className="check-detail">{chk.detail}</span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommended Next Step */}
              <div className="recommendation-box">
                <span className="recommend-icon-badge">
                  <Icon name="shield-check" />
                </span>
                <div className="recommendation-content">
                  <span className="rec-kicker">RECOMMENDED SAFER ALTERNATIVE</span>
                  <p className="rec-body-text">{result.recommendedAction}</p>
                </div>
              </div>

              {/* Limitations & Missing Evidence */}
              <div className="limitations-card">
                <Icon name="info" />
                <div>
                  <span className="limitations-title">Scope and Limitations</span>
                  {result.missingEvidence.length > 0 && (
                    <p className="unverified-alert">
                      <strong>Unverified factors:</strong> {result.missingEvidence.join("; ")}
                    </p>
                  )}
                  {result.limitations.map((item, i) => (
                    <p key={i} style={{ margin: "3px 0" }}>
                      {item}
                    </p>
                  ))}
                </div>
              </div>

              {/* Actions & Live Replay */}
              <div className="result-action-bar">
                <button className="btn-secondary" onClick={() => setShowRaw(!showRaw)} type="button">
                  <Icon name="braces" />
                  {showRaw ? "Hide raw output" : "View raw output"}
                </button>
                <button className="btn-secondary" onClick={() => setShowShareModal(true)} type="button">
                  <Icon name="file-text" />
                  <span>Share / Export Report</span>
                </button>
                {streamingUrl && (
                  <a className="btn-secondary" href={streamingUrl} target="_blank" rel="noreferrer">
                    <Icon name="external-link" />
                    Open sandbox replay
                  </a>
                )}
              </div>

              {showRaw && (
                <pre className="raw-output-viewer">{result.rawAgentOutput || "No raw output recorded."}</pre>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Multi-URL Selection Modal */}
      {showMultiUrlModal && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="multi-url-title">
          <div className="modal-dialog">
            <div className="modal-header">
              <div className="modal-title-row">
                <Icon name="radar" />
                <h3 id="multi-url-title" className="modal-title">
                  Multiple Destination Links Detected
                </h3>
              </div>
              <button
                className="modal-close-btn"
                onClick={() => setShowMultiUrlModal(false)}
                aria-label="Close modal"
                type="button"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p style={{ marginTop: 0 }}>
                AheadGuard does not arbitrarily pick an initial link. Attackers frequently embed legitimate links alongside
                phishing destinations. Choose which destination to inspect in the sandbox:
              </p>

              <div className="url-choice-list">
                {detectedUrls.map((u, i) => {
                  let host = u;
                  try {
                    host = new URL(u).hostname;
                  } catch {
                    // Fallback
                  }
                  return (
                    <label
                      key={i}
                      className={`url-choice-label ${selectedMultiUrl === u ? "selected" : ""}`}
                    >
                      <input
                        type="radio"
                        name="multi-url-target"
                        value={u}
                        checked={selectedMultiUrl === u}
                        onChange={() => setSelectedMultiUrl(u)}
                        className="url-choice-radio"
                      />
                      <div className="url-choice-content">
                        <div className="url-choice-url">{u}</div>
                        <div className="url-choice-domain">Host: {host}</div>
                      </div>
                    </label>
                  );
                })}

                {/* Option for Text-Only analysis without web sandbox */}
                <label
                  className={`url-choice-label ${selectedMultiUrl === "__TEXT_ONLY__" ? "selected" : ""}`}
                >
                  <input
                    type="radio"
                    name="multi-url-target"
                    value="__TEXT_ONLY__"
                    checked={selectedMultiUrl === "__TEXT_ONLY__"}
                    onChange={() => setSelectedMultiUrl("__TEXT_ONLY__")}
                    className="url-choice-radio"
                  />
                  <div className="url-choice-content">
                    <div className="url-choice-url">Analyze message text only</div>
                    <div className="url-choice-domain">
                      Skip web inspection; evaluate claims and recruitment fees from message text.
                    </div>
                  </div>
                </label>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowMultiUrlModal(false)} type="button">
                Cancel
              </button>
              <button className="btn-primary" onClick={handleConfirmMultiUrl} type="button">
                <Icon name="scan-search" />
                <span>Investigate Selected Target</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Share / Export Report Modal */}
      {showShareModal && result && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="share-modal-title">
          <div className="modal-dialog">
            <div className="modal-header">
              <div className="modal-title-row">
                <Icon name="file-text" />
                <h3 id="share-modal-title" className="modal-title">
                  Privacy-Safe Shareable Report
                </h3>
              </div>
              <button
                className="modal-close-btn"
                onClick={() => setShowShareModal(false)}
                aria-label="Close modal"
                type="button"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p style={{ marginTop: 0, fontSize: "12px" }}>
                AheadGuard strips sensitive query parameters (e.g. session tokens, auth keys, OTPs) and masks private
                personal data (emails, phone numbers, government IDs) before export.
              </p>

              {copyStatus && (
                <div
                  style={{
                    background: "rgba(16, 185, 129, 0.15)",
                    color: "var(--risk-low-text)",
                    padding: "8px 12px",
                    borderRadius: "var(--radius-sm)",
                    marginBottom: "10px",
                    fontSize: "12px",
                    fontWeight: 600,
                  }}
                >
                  ✓ {copyStatus}
                </div>
              )}

              {isDemoReport(result) && (
                <div className="demo-banner-sticky" style={{ marginBottom: "10px", padding: "8px 12px" }}>
                  <span className="demo-badge-pill">⚠️ DEMO EXPORT</span>
                  <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                    Exports retain the mandatory offline demonstration disclaimer header to prevent misrepresentation.
                  </span>
                </div>
              )}

              <pre className="share-preview-box">{formatReportMarkdown(result)}</pre>

              <div className="share-action-row">
                <button
                  className="btn-primary"
                  onClick={() => handleCopy(formatReportMarkdown(result), "Markdown")}
                  type="button"
                >
                  <Icon name="file-text" />
                  <span>Copy Markdown</span>
                </button>
                <button
                  className="btn-secondary"
                  onClick={() => handleCopy(formatReportSummary(result), "Summary")}
                  type="button"
                >
                  <span>Copy Summary</span>
                </button>
                <button className="btn-secondary" onClick={() => handleDownloadJson(result)} type="button">
                  <Icon name="braces" />
                  <span>Download JSON</span>
                </button>
                <button className="btn-secondary" onClick={() => window.print()} type="button">
                  <Icon name="eye" />
                  <span>Print / PDF</span>
                </button>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowShareModal(false)} type="button">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Evidence Ledger / Local History */}
      <section className="ledger-panel">
        <div className="ledger-header">
          <div className="ledger-info">
            <span className="section-kicker">03 / EVIDENCE LEDGER</span>
            <h3>Local Investigation History</h3>
            <p>User-controlled evidence records stored locally in your browser. Never transmitted to external servers.</p>
          </div>
          <div className="ledger-action-controls">
            <button
              className="btn-secondary"
              onClick={toggleHistoryPause}
              title={isHistoryPaused ? "Resume recording history" : "Pause recording history"}
              type="button"
            >
              <Icon name={isHistoryPaused ? "play" : "pause"} />
              <span>{isHistoryPaused ? "History Paused" : "Pause History"}</span>
            </button>
            <button
              className="btn-secondary"
              onClick={clearLedger}
              disabled={history.length === 0}
              title="Delete all stored investigation logs"
              type="button"
            >
              <Icon name="trash" />
              <span>Clear All History</span>
            </button>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="ledger-empty-msg">No stored investigations yet. Investigations will appear here.</div>
        ) : (
          <div className="ledger-card-list">
            {history.map((item) => (
              <div
                className="ledger-record-item"
                key={item.investigationId}
                onClick={() => {
                  setResult(item);
                  if (item.replayUrl) setStreamingUrl(item.replayUrl);
                  setStatus(`Viewing archived record · ${item.riskOutcome}`);
                  window.scrollTo({ top: 320, behavior: "smooth" });
                }}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    setResult(item);
                    if (item.replayUrl) setStreamingUrl(item.replayUrl);
                    setStatus(`Viewing archived record · ${item.riskOutcome}`);
                    window.scrollTo({ top: 320, behavior: "smooth" });
                  }
                }}
              >
                <div>
                  <div className="record-url-text">{item.observedDestination?.finalUrl || item.originalUrl}</div>
                  <div className="record-meta-line">
                    <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                    <span>·</span>
                    <span>{item.observedDestination.submittedHost}</span>
                    {item.claimedOrganization && (
                      <>
                        <span>·</span>
                        <span style={{ color: "var(--cyan)" }}>{item.claimedOrganization}</span>
                      </>
                    )}
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <span
                    className="metric-pill"
                    style={{
                      borderColor:
                        item.riskOutcome === "High risk"
                          ? "var(--risk-high-text)"
                          : item.riskOutcome === "Suspicious"
                          ? "var(--risk-suspicious-text)"
                          : item.riskOutcome === "Low observed risk"
                          ? "var(--risk-low-text)"
                          : "var(--border-cyan)",
                      color:
                        item.riskOutcome === "High risk"
                          ? "var(--risk-high-text)"
                          : item.riskOutcome === "Suspicious"
                          ? "var(--risk-suspicious-text)"
                          : item.riskOutcome === "Low observed risk"
                          ? "var(--risk-low-text)"
                          : "var(--cyan)",
                    }}
                  >
                    {item.riskOutcome}
                  </span>
                  <Icon name="arrow-up-right" />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* The AheadGuard Principle Section */}
      <section className="principle-panel">
        <div className="principle-header">
          <span className="section-kicker">THE AHEADGUARD PRINCIPLE</span>
          <h2>Investigate before you act.</h2>
        </div>
        <div className="principle-steps-row">
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="eye" />
            </span>
            <strong>01. Notice</strong>
            <span>Capture message, link, or offer</span>
          </div>
          <div className="step-arrow-divider">→</div>
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="search-check" />
            </span>
            <strong>02. Investigate</strong>
            <span>Probe sandbox & verify registry</span>
          </div>
          <div className="step-arrow-divider">→</div>
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="brain-circuit" />
            </span>
            <strong>03. Understand</strong>
            <span>Claim-by-claim evidence ledger</span>
          </div>
          <div className="step-arrow-divider">→</div>
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="shield-check" />
            </span>
            <strong>04. Protect</strong>
            <span>Direct to official independent routes</span>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-brand">
          <span className="brand-mark" style={{ width: "28px", height: "30px" }}>
            <ShieldIcon />
          </span>
          <span className="brand-title" style={{ fontSize: "15px" }}>
            AheadGuard <span className="brand-accent">AI</span>
          </span>
        </div>
        <p className="footer-copy">
          AheadGuard AI Digital Trust & Scam Verification Guardian. Grounded strictly in observable evidence.
          Does not replace client-side antivirus or operating system safeguards.
        </p>
        <span className="footer-pill">EVIDENCE-BACKED SAFETY GUARDIAN</span>
      </footer>
    </main>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 64 72" fill="none" aria-hidden="true">
      <path
        d="M32 3 58 13v20c0 17-11 27-26 36C17 60 6 50 6 33V13L32 3Z"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path
        d="M32 12 49 18v15c0 12-7 19-17 25-10-6-17-13-17-25V18l17-6Z"
        fill="currentColor"
        fillOpacity=".15"
        stroke="currentColor"
        strokeWidth="2"
      />
      <path
        d="m22 39 8-17 12 28"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Spinner() {
  return <span className="spinner" />;
}

function Icon({ name }: { name: string }) {
  const paths: Record<string, ReactNode> = {
    scan: (
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m16 16 4 4M7 11h8M11 7v8" />
      </>
    ),
    search: (
      <>
        <circle cx="10.5" cy="10.5" r="6.5" />
        <path d="m16 16 4 4" />
      </>
    ),
    "file-text": (
      <>
        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
        <path d="M13 2v7h7M8 13h8M8 17h8" />
      </>
    ),
    shield: (
      <>
        <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
        <path d="m9 12 2 2 4-4" />
      </>
    ),
    link: (
      <>
        <path d="M10 13a5 5 0 0 0 7.07 0l3-3A5 5 0 0 0 13 2.93l-1.72 1.72" />
        <path d="M14 11a5 5 0 0 0-7.07 0l-3 3A5 5 0 0 0 11 21.07l1.72-1.72" />
      </>
    ),
    activity: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
    "alert-triangle": (
      <>
        <path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3l-8-14a2 2 0 0 0-3.4-.1Z" />
        <path d="M12 9v4m0 4h.01" />
      </>
    ),
    radar: (
      <>
        <circle cx="12" cy="12" r="10" />
        <circle cx="12" cy="12" r="6" />
        <path d="m12 12 7-7" />
      </>
    ),
    "shield-alert": (
      <>
        <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
        <path d="M12 8v4m0 4h.01" />
      </>
    ),
    "shield-check": (
      <>
        <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    "circle-help": (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3m.1 4h.01" />
      </>
    ),
    "external-link": (
      <>
        <path d="M15 3h6v6M10 14 21 3" />
        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      </>
    ),
    "alert-circle": (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M12 8v4m0 4h.01" />
      </>
    ),
    "check-circle": (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    info: (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M12 11v5m0-8h.01" />
      </>
    ),
    lock: (
      <>
        <rect x="3" y="11" width="18" height="10" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    braces: (
      <>
        <path d="M8 3H6a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h2M16 3h2a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-2" />
      </>
    ),
    eye: (
      <>
        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
        <circle cx="12" cy="12" r="3" />
      </>
    ),
    "search-check": (
      <>
        <circle cx="10.5" cy="10.5" r="6.5" />
        <path d="m16 16 4 4m-11-9 2 2 4-4" />
      </>
    ),
    "brain-circuit": (
      <>
        <path d="M12 18V5a3 3 0 0 0-5.8-1A4 4 0 0 0 4 11a4 4 0 0 0 3 7h5Zm0-8h4a4 4 0 0 1 0 8h-4M12 5h3a3 3 0 0 1 2.8 4M7 8h1m-1 6h1m8-2h1" />
      </>
    ),
    "arrow-up-right": <path d="M7 17 17 7M7 7h10v10" />,
    "scan-search": (
      <>
        <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
        <circle cx="10.5" cy="10.5" r="4.5" />
        <path d="m14 14 4 4" />
      </>
    ),
    pause: (
      <>
        <rect x="6" y="4" width="4" height="16" />
        <rect x="14" y="4" width="4" height="16" />
      </>
    ),
    play: <polygon points="5 3 19 12 5 21 5 3" />,
    trash: (
      <>
        <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
      </>
    ),
    briefcase: (
      <>
        <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
        <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
      </>
    ),
    sparkles: (
      <>
        <path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z" />
      </>
    ),
    map: (
      <>
        <polygon points="3 6 9 3 15 6 21 3 21 18 15 21 9 18 3 21" />
        <line x1="9" x2="9" y1="3" y2="18" />
        <line x1="15" x2="15" y1="6" y2="21" />
      </>
    ),
  };
  return (
    <svg
      className="icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={{ width: "16px", height: "16px", display: "inline-block", verticalAlign: "middle" }}
    >
      {paths[name] ?? paths.info}
    </svg>
  );
}
