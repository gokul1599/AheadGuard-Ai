"use client";

import React, { useState } from "react";
import Link from "next/link";

export default function InstallExtensionPage() {
  const [downloadStarted, setDownloadStarted] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [activeStep, setActiveStep] = useState<number | null>(null);

  const handleDownload = () => {
    setDownloadStarted(true);
    // Trigger download
    const link = document.createElement("a");
    link.href = "/aheadguard-ai-chrome-extension.zip";
    link.download = "aheadguard-ai-chrome-extension.zip";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => {
      setDownloadStarted(false);
    }, 6000);
  };

  const handleCopyChromeUrl = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText("chrome://extensions");
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 3000);
    }
  };

  const scrollToGuide = () => {
    const el = document.getElementById("installation-steps");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="install-page-shell">
      {/* Top Bar */}
      <header className="topbar">
        <Link className="brand" href="/" aria-label="AheadGuard AI home">
          <span className="brand-mark">
            <svg viewBox="0 0 64 72" fill="none" aria-hidden="true" width="28" height="32">
              <path d="M32 3 58 13v20c0 17-11 27-26 36C17 60 6 50 6 33V13L32 3Z" stroke="#00d2ff" strokeWidth="3" />
              <path d="M32 12 49 18v15c0 12-7 19-17 25-10-6-17-13-17-25V18l17-6Z" fill="#00d2ff" fillOpacity=".15" stroke="#00d2ff" strokeWidth="2" />
              <path d="m22 39 8-17 12 28" stroke="#00d2ff" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <span className="brand-text">
            <span className="brand-title">
              AheadGuard <span className="brand-accent">AI</span>
            </span>
            <span className="brand-subtitle">CHROME EXTENSION INSTALLER</span>
          </span>
        </Link>
        <div className="topbar-right">
          <span className="engine-status-badge" role="status" aria-live="polite">
            <span className="status-dot" /> Extension v3.0.0 Ready
          </span>
          <Link href="/" className="install-nav-link">
            ← Web App
          </Link>
          <button
            type="button"
            className="btn-download-primary header-download-btn"
            onClick={handleDownload}
            aria-label="Download Extension ZIP"
          >
            <span className="btn-icon">⬇</span>
            <span>Download Extension</span>
          </button>
        </div>
      </header>

      {/* Floating Download Notification Banner */}
      {downloadStarted && (
        <aside className="download-toast-banner" role="status" aria-live="polite" aria-label="Download notification">
          <div className="download-toast-content">
            <span className="toast-icon">✓</span>
            <div>
              <strong>Download initiated: aheadguard-ai-chrome-extension.zip</strong>
              <p>Extract the ZIP file, open <code>chrome://extensions</code>, enable Developer Mode, and click Load unpacked.</p>
            </div>
          </div>
          <button
            type="button"
            className="toast-close-btn"
            onClick={() => setDownloadStarted(false)}
            aria-label="Close notification"
          >
            ✕
          </button>
        </aside>
      )}

      {/* Hero Section */}
      <section className="install-hero">
        <div className="install-hero-content">
          <div className="install-eyebrow">
            <span className="eyebrow-line" /> MANIFEST V3 · DIRECT INSTALLATION
          </div>
          <h1 className="install-headline">
            Your Digital Protection,
            <br />
            <span className="gradient-text">Right Inside Your Browser.</span>
          </h1>
          <p className="install-description">
            Install AheadGuard AI&apos;s browser extension and check suspicious job offers, links and digital interactions
            while browsing.
          </p>

          <div className="install-cta-group">
            <button
              type="button"
              className="btn-download-primary hero-btn-lg"
              onClick={handleDownload}
              aria-label="Download AheadGuard AI for Chrome"
            >
              <span className="btn-icon-lg">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" width="20" height="20">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
              </span>
              <span className="btn-text-block">
                <span className="btn-main-label">Download for Chrome</span>
                <span className="btn-sub-label">Version 3.0.0 ZIP · 27 KB · Manifest V3</span>
              </span>
            </button>

            <button
              type="button"
              className="btn-guide-secondary hero-btn-lg"
              onClick={scrollToGuide}
              aria-label="View Installation Guide"
            >
              <span>View Installation Guide ↓</span>
            </button>
          </div>

          <div className="install-pill-row">
            <span className="install-pill">
              <span className="pill-dot" /> Chromium Manifest V3
            </span>
            <span className="install-pill">
              <span className="pill-dot" /> Developer Mode Unpacked
            </span>
            <span className="install-pill">
              <span className="pill-dot" /> Zero Credential Access
            </span>
            <span className="install-pill">
              <span className="pill-dot" /> Local Evidence Ledger
            </span>
          </div>
        </div>

        {/* Hero Graphic / Extension Preview */}
        <div className="install-hero-visual" aria-hidden="true">
          <div className="ext-preview-frame">
            <div className="ext-preview-topbar">
              <div className="ext-preview-dots">
                <span className="dot red" />
                <span className="dot yellow" />
                <span className="dot green" />
              </div>
              <span className="ext-preview-url">chrome-extension://aheadguard/popup.html</span>
            </div>
            <div className="ext-preview-body">
              <div className="preview-header">
                <div className="preview-brand">
                  <svg viewBox="0 0 64 72" fill="none" width="18" height="20">
                    <path d="M32 3 58 13v20c0 17-11 27-26 36C17 60 6 50 6 33V13L32 3Z" stroke="#00d2ff" strokeWidth="3" />
                  </svg>
                  <div>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "#f8fafc" }}>
                      AheadGuard <span style={{ color: "#00d2ff" }}>AI</span>
                    </div>
                    <div style={{ fontSize: "8px", color: "#8295ac", letterSpacing: "0.05em" }}>
                      PRE-ACTION GUARDIAN
                    </div>
                  </div>
                </div>
                <span className="preview-badge-status">PROTECTION ON</span>
              </div>

              <div className="preview-card-dest">
                <span style={{ fontSize: "9px", color: "#8295ac", textTransform: "uppercase" }}>Active Destination</span>
                <span style={{ fontSize: "12px", fontFamily: "var(--font-mono)", color: "#38bdf8", wordBreak: "break-all" }}>
                  https://careers.google.com/jobs/results
                </span>
              </div>

              <div className="preview-result-card">
                <div className="preview-risk-row">
                  <span className="preview-shield-icon">🛡️</span>
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: "700", color: "#10b981" }}>LOW OBSERVED RISK</div>
                    <div style={{ fontSize: "10px", color: "#cbd5e1" }}>Destination verified against official corporate domains.</div>
                  </div>
                </div>
              </div>

              <div className="preview-action-row">
                <span className="preview-btn-mock">Investigate Link</span>
                <span className="preview-btn-mock primary">Open Full Ledger</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Compatibility & Security Disclosure Strip */}
      <section className="install-disclosure-strip" aria-label="Compatibility and safety notices">
        <div className="disclosure-grid">
          <div className="disclosure-card">
            <div className="disclosure-icon">🌐</div>
            <div className="disclosure-text">
              <h3>Supported Browsers</h3>
              <p>
                Engineered for all modern Chromium-based browsers: <strong>Google Chrome</strong>, <strong>Microsoft Edge</strong>, <strong>Brave</strong>, <strong>Opera</strong>, and <strong>Arc</strong>.
                <span className="text-muted-inline"> Firefox and Safari are not yet supported for direct unpacked installation.</span>
              </p>
            </div>
          </div>

          <div className="disclosure-card">
            <div className="disclosure-icon">⚙️</div>
            <div className="disclosure-text">
              <h3>Developer Mode Installation</h3>
              <p>
                AheadGuard AI is distributed as an open, inspectable ZIP package. Enabling Developer Mode in Chrome is required to load unpacked extensions. Chrome may display a standard manual loading note.
              </p>
            </div>
          </div>

          <div className="disclosure-card">
            <div className="disclosure-icon">🔒</div>
            <div className="disclosure-text">
              <h3>Zero Sensitive Data Collection</h3>
              <p>
                AheadGuard AI never requests or inspects passwords, credit card numbers, OTPs, or private chat histories. It evaluates only destination URLs and user-submitted offer text. We never ask you to disable browser security.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Installation Steps Section */}
      <section className="install-steps-section" id="installation-steps" aria-label="Step by step installation guide">
        <div className="section-head">
          <div className="eyebrow">
            <span className="eyebrow-line" /> ZERO BUILD COMMANDS REQUIRED
          </div>
          <h2>Step-by-Step Installation Guide</h2>
          <p>
            Follow these 7 steps to install and start using AheadGuard AI in Chrome or any Chromium browser in under two minutes.
          </p>
        </div>

        <div className="steps-container">
          {/* Step 1 */}
          <div
            className={`step-card ${activeStep === 1 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(1)}
          >
            <div className="step-badge">01</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 1 — Download</h3>
                <span className="step-tag">Initial Step</span>
              </div>
              <p>
                Click <strong>Download for Chrome</strong> to download the AheadGuard AI extension ZIP file (<code>aheadguard-ai-chrome-extension.zip</code>) to your computer.
              </p>
              <div className="step-action-row">
                <button
                  type="button"
                  className="step-inline-btn"
                  onClick={handleDownload}
                  aria-label="Download ZIP in Step 1"
                >
                  <span>⬇ Download aheadguard-ai-chrome-extension.zip</span>
                </button>
                <span className="step-meta-info">27 KB · Pre-compiled release</span>
              </div>
            </div>
          </div>

          {/* Step 2 */}
          <div
            className={`step-card ${activeStep === 2 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(2)}
          >
            <div className="step-badge">02</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 2 — Extract</h3>
                <span className="step-tag">File System</span>
              </div>
              <p>
                Extract the downloaded ZIP file into a permanent folder on your computer (for example, in your <code>Documents</code> or <code>Development</code> directory).
              </p>
              <div className="step-callout warning">
                <span className="callout-icon">💡</span>
                <span>
                  <strong>Keep the extracted folder permanent:</strong> Chrome runs the extension directly from this directory. Do not delete or move the folder after loading it.
                </span>
              </div>
            </div>
          </div>

          {/* Step 3 */}
          <div
            className={`step-card ${activeStep === 3 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(3)}
          >
            <div className="step-badge">03</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 3 — Open Chrome Extensions</h3>
                <span className="step-tag">Browser Navigation</span>
              </div>
              <p>
                Open a new tab in Google Chrome and navigate to the Extensions management page:
              </p>
              <div className="step-code-box">
                <code>chrome://extensions</code>
                <button
                  type="button"
                  className="copy-code-btn"
                  onClick={handleCopyChromeUrl}
                  aria-label="Copy chrome://extensions to clipboard"
                >
                  {copiedUrl ? "✓ Copied!" : "Copy Address"}
                </button>
              </div>
              <p className="step-sub-note">
                (You can also click Chrome&apos;s three-dot menu → <strong>Extensions</strong> → <strong>Manage Extensions</strong>).
              </p>
            </div>
          </div>

          {/* Step 4 */}
          <div
            className={`step-card ${activeStep === 4 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(4)}
          >
            <div className="step-badge">04</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 4 — Enable Developer Mode</h3>
                <span className="step-tag">Browser Setting</span>
              </div>
              <p>
                Turn on the <strong>Developer mode</strong> toggle located in the top-right corner of the Extensions page.
              </p>
              <div className="step-visual-mockup">
                <div className="mockup-toggle-row">
                  <span className="mockup-label">Developer mode</span>
                  <div className="mockup-switch on">
                    <span className="mockup-switch-knob" />
                  </div>
                </div>
              </div>
              <p className="step-sub-note">
                Enabling Developer mode unlocks the &quot;Load unpacked&quot; button needed for direct ZIP installation.
              </p>
            </div>
          </div>

          {/* Step 5 */}
          <div
            className={`step-card ${activeStep === 5 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(5)}
          >
            <div className="step-badge">05</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 5 — Load the Extension</h3>
                <span className="step-tag">Load Unpacked</span>
              </div>
              <p>
                Click the <strong>Load unpacked</strong> button in the top-left menu bar, then browse to and select the extracted folder containing <code>manifest.json</code>.
              </p>
              <div className="step-visual-mockup">
                <div className="mockup-action-bar">
                  <span className="mockup-btn active-btn">[ Load unpacked ]</span>
                  <span className="mockup-btn">Pack extension</span>
                  <span className="mockup-btn">Update</span>
                </div>
              </div>
              <p className="step-sub-note">
                Confirm that <strong>AheadGuard AI — Proactive Digital Safety Guardian</strong> appears in your extension cards list.
              </p>
            </div>
          </div>

          {/* Step 6 */}
          <div
            className={`step-card ${activeStep === 6 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(6)}
          >
            <div className="step-badge">06</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 6 — Pin AheadGuard AI</h3>
                <span className="step-tag">Chrome Toolbar</span>
              </div>
              <p>
                Click the puzzle-piece icon (<strong>Extensions</strong>) in Chrome&apos;s toolbar, locate AheadGuard AI, and click the <strong>Pin</strong> icon to keep it visible on your browser toolbar.
              </p>
              <div className="step-visual-mockup">
                <div className="mockup-pin-row">
                  <span className="mockup-puzzle">🧩 Extensions</span>
                  <span className="mockup-pin-item">
                    🛡️ AheadGuard AI <span className="pin-symbol active">📌</span>
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Step 7 */}
          <div
            className={`step-card ${activeStep === 7 ? "active" : ""}`}
            onMouseEnter={() => setActiveStep(7)}
          >
            <div className="step-badge">07</div>
            <div className="step-body">
              <div className="step-title-row">
                <h3>Step 7 — Start Using</h3>
                <span className="step-tag">Ready</span>
              </div>
              <p>
                Click the AheadGuard shield icon in your browser toolbar to open the extension popup. You can:
              </p>
              <ul className="step-feature-checklist">
                <li>
                  <strong>Observe Active Page Safety:</strong> View automated destination checks and safety badges for the page you are currently viewing.
                </li>
                <li>
                  <strong>Check Custom Links:</strong> Paste suspicious links or messages containing URLs into the &quot;Check custom link&quot; box.
                </li>
                <li>
                  <strong>Verify Settings:</strong> Ensure your backend is configured to <code>https://aheadguard-ai.vercel.app</code>.
                </li>
                <li>
                  <strong>Inspect Recent Checks:</strong> Access your local, privacy-first Evidence Ledger of past investigations.
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Real Capabilities Matrix */}
      <section className="install-capabilities-section" aria-label="Implemented capabilities">
        <div className="section-head">
          <div className="eyebrow">
            <span className="eyebrow-line" /> VERIFIED CAPABILITIES
          </div>
          <h2>What AheadGuard AI Extension Does</h2>
          <p>
            AheadGuard operates on strict digital trust principles. Here is what is genuinely implemented and active:
          </p>
        </div>

        <div className="capabilities-grid">
          <div className="cap-card">
            <div className="cap-icon">🛡️</div>
            <h3>Pre-Action Destination Probing</h3>
            <p>
              Monitors active browser tabs via <code>chrome.webNavigation</code> and checks top-level domains against malicious patterns, suspicious TLDs, and known phishing indicators.
            </p>
          </div>

          <div className="cap-card">
            <div className="cap-icon">🔍</div>
            <h3>Direct Scam & Offer Analysis</h3>
            <p>
              Directly integrates with AheadGuard&apos;s live backend API to analyze employment offers, upfront payment demands, and recruiter domain consistency.
            </p>
          </div>

          <div className="cap-card">
            <div className="cap-icon">⚠️</div>
            <h3>Action & Consequence Previews</h3>
            <p>
              Provides explicit warnings about what could happen if you proceed (e.g., credential theft, upfront fee traps, or brand impersonation).
            </p>
          </div>

          <div className="cap-card">
            <div className="cap-icon">📖</div>
            <h3>Local Privacy-Preserving Ledger</h3>
            <p>
              Stores up to 25 recent investigations strictly in your browser&apos;s local <code>chrome.storage.local</code>. Can be cleared or paused at any time in Extension Settings.
            </p>
          </div>

          <div className="cap-card">
            <div className="cap-icon">🛑</div>
            <h3>Zero Password & OTP Access</h3>
            <p>
              Our content script is completely isolated and strictly avoids observing password fields, credit card inputs, banking portals, or private messaging content.
            </p>
          </div>

          <div className="cap-card">
            <div className="cap-icon">⚡</div>
            <h3>Production Cloud Backend</h3>
            <p>
              Pre-configured to communicate securely with AheadGuard&apos;s verified production cluster at <code>https://aheadguard-ai.vercel.app</code>.
            </p>
          </div>
        </div>
      </section>

      {/* Release Verification & Checksums */}
      <section className="install-release-box" aria-label="Release verification and checksums">
        <div className="release-box-head">
          <h3>Production Release Verification</h3>
          <span className="release-verified-badge">✓ CRYPTOGRAPHICALLY VERIFIED</span>
        </div>
        <div className="release-specs-grid">
          <div className="spec-item">
            <span className="spec-label">Package Name</span>
            <span className="spec-val">aheadguard-ai-chrome-extension.zip</span>
          </div>
          <div className="spec-item">
            <span className="spec-label">Version</span>
            <span className="spec-val">v3.0.0 (Production Build)</span>
          </div>
          <div className="spec-item">
            <span className="spec-label">Manifest Specification</span>
            <span className="spec-val">Manifest V3 (MV3)</span>
          </div>
          <div className="spec-item">
            <span className="spec-label">Package Size</span>
            <span className="spec-val">~27 KB (9 distribution files)</span>
          </div>
          <div className="spec-item full-width">
            <span className="spec-label">SHA-256 Checksum</span>
            <code className="checksum-code">
              497e41e3cd1f1f8616edefe62103d5394d4550d435ad4adfbfd3bb8691751841
            </code>
          </div>
        </div>
        <div className="release-actions">
          <button type="button" className="btn-download-primary" onClick={handleDownload}>
            <span>Download Verified Package (ZIP)</span>
          </button>
          <a
            href="/extension-release.json"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-release-meta"
          >
            View Release Metadata JSON ↗
          </a>
        </div>
      </section>

      {/* Footer */}
      <footer className="install-page-footer">
        <div className="footer-content">
          <div className="footer-brand">
            AheadGuard <span className="brand-accent">AI</span> · Pre-Action Digital Safety
          </div>
          <div className="footer-links">
            <Link href="/">Web App</Link>
            <a href="/aheadguard-ai-chrome-extension.zip" download="aheadguard-ai-chrome-extension.zip">
              Direct ZIP Link
            </a>
            <a href="https://github.com/gokul1599/AheadGuard-Ai" target="_blank" rel="noopener noreferrer">
              GitHub Repository ↗
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
