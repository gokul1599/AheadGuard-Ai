"use client";

import { useState, useEffect, useRef } from "react";
import type { ReactNode } from "react";
import type { InvestigationReport } from "@/lib/types";

const EXAMPLES = [
  { label: "Scaler Official", value: "https://www.scaler.com" },
  { label: "Wikipedia", value: "https://en.wikipedia.org/wiki/Computer_security" },
  { label: "Phishing / Urgent Alert", value: "https://portal-account-verify.online/login?action=verify_now" },
  { label: "Lookalike Punycode", value: "https://xn--gogle-pra.com/signin" },
];

export default function Home() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("Ready for destination check");
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [result, setResult] = useState<InvestigationReport | null>(null);
  const [streamingUrl, setStreamingUrl] = useState<string | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [activeTab, setActiveTab] = useState<"evidence" | "facts" | "checks">("evidence");

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

    // Check for deep-link URL parameter (?url=... or ?target=...)
    try {
      const params = new URLSearchParams(window.location.search);
      const urlParam = params.get("url") || params.get("target");
      if (urlParam) {
        const decoded = decodeURIComponent(urlParam).trim();
        setInput(decoded);

        // If we already have a recorded report in the ledger for this destination, surface it immediately
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

  // Save report to ledger unless paused
  const saveToLedger = (report: InvestigationReport) => {
    if (isHistoryPaused) return;
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

  async function investigate() {
    if (!input.trim() || loading) return;

    setError(null);
    setResult(null);
    setStreamingUrl(undefined);
    setShowRaw(false);
    setProgressLog([]);
    setLoading(true);
    setStatus("Initiating live investigation…");

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
        body: JSON.stringify({ input }),
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
          // Response body was not JSON
        }
        throw new Error(errorMsg);
      }

      // Check if response is an SSE stream
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("text/event-stream") && response.body) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

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
            const dataRaw = dataLines.join("\n");

            try {
              const parsed = JSON.parse(dataRaw);
              if (eventType === "started") {
                setStatus(parsed.message);
                addLog(`[SESSION] ${parsed.message}`);
              } else if (eventType === "streaming_url") {
                setStreamingUrl(parsed.streamingUrl);
                addLog(`[STREAM] Live replay URL generated`);
              } else if (eventType === "progress") {
                setStatus(parsed.message);
                addLog(`[PROGRESS] ${parsed.message}`);
              } else if (eventType === "heartbeat") {
                // Heartbeat
              } else if (eventType === "complete") {
                setStatus("Finalizing evidence assessment…");
                addLog(`[COMPLETED] Remote browser execution finished`);
              } else if (eventType === "report") {
                const rep = (parsed.report || parsed) as InvestigationReport;
                setResult(rep);
                if (rep.replayUrl) setStreamingUrl(rep.replayUrl);
                saveToLedger(rep);
                setStatus(`Investigation completed · ${rep.riskOutcome}`);
                addLog(`[ASSESSMENT] Policy engine classified: ${rep.riskOutcome}`);
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
          }
        }
      } else {
        // Fallback for regular JSON response
        const data = await response.json();
        if (data.report) {
          setResult(data.report);
          if (data.report.replayUrl) setStreamingUrl(data.report.replayUrl);
          saveToLedger(data.report);
          setStatus(`Investigation complete · ${data.report.riskOutcome}`);
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

  const riskClass =
    result?.riskOutcome === "High risk"
      ? "risk-high"
      : result?.riskOutcome === "Suspicious"
      ? "risk-suspicious"
      : result?.riskOutcome === "Low observed risk"
      ? "risk-low"
      : "risk-unknown";

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
            <span className="brand-subtitle">PRE-ACTION DIGITAL SAFETY GUARDIAN</span>
          </span>
        </a>
        <div className="topbar-right">
          <span className="engine-status-badge" role="status" aria-live="polite">
            <span className="status-dot" /> TinyFish Engine Active
          </span>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="eyebrow-line" /> PRE-ACTION SAFETY ENGINE
          </div>
          <h1>
            Your AI checks first.
            <br />
            <span className="gradient-text">You act with confidence.</span>
          </h1>
          <p>
            AheadGuard investigates unknown destinations, phishing traps, and deceptive links before you commit.
            It observes real behavior inside an isolated browser, simulates consequences, and recommends verified paths.
          </p>
          <div className="feature-pill-row">
            <span className="feature-pill">
              <Icon name="radar" /> Constrained Sandbox
            </span>
            <span className="feature-pill">
              <Icon name="search" /> TinyFish Probe
            </span>
            <span className="feature-pill">
              <Icon name="eye" /> Action Preview
            </span>
            <span className="feature-pill">
              <Icon name="shield" /> Deterministic Policy
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
              <span className="status-dot blinking" /> ENGINE READY
            </span>
            <span>READ-ONLY ISOLATION</span>
          </div>
        </div>
      </section>

      {/* Main Workspace Grid */}
      <section className="workspace-grid">
        {/* Panel 1: Input */}
        <div className="panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">01 / CHECK BEFORE I ACT</span>
              <h2>Submit target link or message</h2>
            </div>
            <span className="panel-icon-badge">
              <Icon name="link" />
            </span>
          </div>
          <p className="panel-description">
            Enter a destination link or paste an unexpected message. AheadGuard initiates a strictly read-only
            investigation using TinyFish, inspects redirects and form elements, and evaluates warning indicators.
          </p>

          <div className="input-label-row">
            <label className="input-label" htmlFor="target-input">
              Destination URL or message
            </label>
            <span className="char-count">{input.length}/4000</span>
          </div>

          <div className="input-textarea-wrapper">
            <textarea
              id="target-input"
              className="input-textarea"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="https://example.com or paste an unexpected message with a link…"
              maxLength={4000}
              disabled={loading}
              aria-describedby="input-helper-note"
            />
          </div>

          <div className="input-meta-bar" id="input-helper-note">
            <span>Never paste passwords, OTPs, or private account data.</span>
          </div>

          {/* Quick Fills */}
          <div className="scenario-section">
            <span className="scenario-title">TEST SCENARIOS</span>
            <div className="scenario-chips">
              {EXAMPLES.map((ex) => (
                <button
                  className="scenario-btn"
                  key={ex.label}
                  onClick={() => setInput(ex.value)}
                  disabled={loading}
                  type="button"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          </div>

          <button
            className="btn-primary"
            onClick={investigate}
            disabled={loading || input.trim().length < 4}
            type="button"
          >
            {loading ? <Spinner /> : <Icon name="scan-search" />}
            <span>{loading ? "Investigating destination…" : "Investigate Destination"}</span>
            <Icon name="arrow-up-right" />
          </button>

          <div className="boundary-notice">
            <Icon name="lock" />
            <span>
              <strong>Read-only boundary enforced:</strong> The investigator will not log in, submit forms, execute files,
              or follow prompt instructions attempting to hijack the investigation.
            </span>
          </div>
        </div>

        {/* Panel 2: Investigation Findings */}
        <div className="panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">02 / EVIDENCE & VERDICT</span>
              <h2>Investigation report</h2>
            </div>
            <span className="panel-icon-badge">
              <Icon name="activity" />
            </span>
          </div>

          <div className="status-bar" role="status" aria-live="polite">
            <span className={loading ? "status-dot blinking" : "status-dot"} />
            <span>{status}</span>
            <span className="status-pill-end">{loading ? "STREAMING" : "LIVE STATUS"}</span>
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

          {/* Error Card */}
          {error && (
            <div className="alert-card-danger" role="alert">
              <div className="alert-head">
                <Icon name="alert-triangle" />
                <span>Investigation Alert</span>
              </div>
              <p>{error}</p>
              {error.includes("TINYFISH_API_KEY") && (
                <code>Add TINYFISH_API_KEY=your_key to .env.local and restart the server.</code>
              )}
            </div>
          )}

          {/* Empty State */}
          {!result && !error && (
            <div className="empty-hud">
              <div className="empty-hud-icon">
                <Icon name="radar" />
              </div>
              <h3>{loading ? "Investigating destination" : "Investigation has not run yet"}</h3>
              <p>
                {loading
                  ? "TinyFish remote browser is inspecting the destination page and redirect chain in an isolated sandbox. Please wait…"
                  : "Submit a public URL to start a genuine investigation. AheadGuard will never guess or label an unverified site safe."}
              </p>
              <div className="step-roadmap">
                <div className={`roadmap-item ${loading ? "active" : ""}`}>
                  <span className="item-num">01</span> Validate protocol and network safety
                </div>
                <div className={`roadmap-item ${loading ? "active" : ""}`}>
                  <span className="item-num">02</span> Execute read-only TinyFish inspection
                </div>
                <div className={`roadmap-item ${result ? "active" : ""}`}>
                  <span className="item-num">03</span> Ground findings in deterministic policy
                </div>
              </div>
            </div>
          )}

          {/* Active Result View */}
          {result && (
            <div className="assessment-container">
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

                  {/* Mandatory Low Risk Disclaimer */}
                  {result.riskOutcome === "Low observed risk" && (
                    <div className="safety-disclaimer-callout">
                      <Icon name="info" />
                      <span>
                        <strong>Notice:</strong> Low observed risk indicates no active warning signals were found during this probe. It is not an absolute guarantee of safety.
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Action Preview */}
              <div className="action-preview-card">
                <div className="action-preview-head">
                  <span className="action-preview-title">
                    <Icon name="eye" /> Action Preview: Consequence Simulation
                  </span>
                  <span className="action-badge">{result.actionPreview.proposedAction}</span>
                </div>
                <p className="action-consequence-text">{result.actionPreview.consequenceIfProceed}</p>
                {result.actionPreview.riskFactors.length > 0 && (
                  <ul className="risk-factor-list">
                    {result.actionPreview.riskFactors.map((factor, i) => (
                      <li key={i}>{factor}</li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Destination & Redirection Summary */}
              <div className="destination-meta-card">
                <div>
                  <span className="meta-field-label">SUBMITTED HOST</span>
                  <div className="meta-field-value">{result.observedDestination.submittedHost}</div>
                </div>

                {result.observedDestination.destinationChanged && (
                  <div className="redirect-alert-row">
                    <Icon name="alert-circle" />
                    <span>
                      Redirect detected: Final host resolved to <strong>{result.observedDestination.finalHost || "external domain"}</strong>
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

              {/* Tabs for Evidence, Facts, and Checks */}
              <div className="tab-navigation" role="tablist">
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
                  Observed Facts vs Interpretations
                </button>
                <button
                  className={`tab-btn ${activeTab === "checks" ? "active" : ""}`}
                  onClick={() => setActiveTab("checks")}
                  role="tab"
                  aria-selected={activeTab === "checks"}
                  type="button"
                >
                  Checks Performed ({result.checksPerformed.length})
                </button>
              </div>

              {/* Tab 1: Evidence Items */}
              {activeTab === "evidence" && (
                <div className="findings-container" role="tabpanel">
                  {result.evidenceItems.map((item, idx) => (
                    <div className="finding-card" key={idx}>
                      <span className={`finding-icon-wrap ${item.kind === "warning" ? "warning" : item.kind === "positive" ? "positive" : "neutral"}`}>
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

              {/* Tab 2: Observed Facts vs Interpretations */}
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

              {/* Tab 3: Checks Performed */}
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
                    <p key={i} style={{ margin: "3px 0" }}>{item}</p>
                  ))}
                </div>
              </div>

              {/* Actions & Replay */}
              <div className="result-action-bar">
                <button
                  className="btn-secondary"
                  onClick={() => setShowRaw(!showRaw)}
                  type="button"
                >
                  <Icon name="braces" />
                  {showRaw ? "Hide raw output" : "View raw output"}
                </button>
                {streamingUrl && (
                  <a className="btn-secondary" href={streamingUrl} target="_blank" rel="noreferrer">
                    <Icon name="external-link" />
                    Open live browser replay
                  </a>
                )}
              </div>

              {showRaw && <pre className="raw-output-viewer">{result.rawAgentOutput || "No raw output recorded."}</pre>}
            </div>
          )}
        </div>
      </section>

      {/* Evidence Ledger / Local History */}
      <section className="ledger-panel">
        <div className="ledger-header">
          <div className="ledger-info">
            <span className="section-kicker">03 / EVIDENCE LEDGER</span>
            <h3>Local Investigation History</h3>
            <p>
              User-controlled evidence records stored in your browser. Never transmitted to external servers.
            </p>
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
                  <div className="record-url-text">{item.originalUrl}</div>
                  <div className="record-meta-line">
                    <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                    <span>·</span>
                    <span>{item.observedDestination.submittedHost}</span>
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
            <span>Capture link or input event</span>
          </div>
          <div className="step-arrow-divider">→</div>
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="search-check" />
            </span>
            <strong>02. Investigate</strong>
            <span>TinyFish constrained probe</span>
          </div>
          <div className="step-arrow-divider">→</div>
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="brain-circuit" />
            </span>
            <strong>03. Understand</strong>
            <span>Deterministic policy engine</span>
          </div>
          <div className="step-arrow-divider">→</div>
          <div className="principle-step-col">
            <span className="step-icon-circle">
              <Icon name="shield-check" />
            </span>
            <strong>04. Protect</strong>
            <span>Explain & recommend safer path</span>
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
          AheadGuard AI Decision-Support Guardian. Grounded strictly in observable evidence. Does
          not replace client-side antivirus or operating system safeguards.
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
