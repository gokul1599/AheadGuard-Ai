"use client";

import React from "react";
import { InvestigationReport } from "../lib/types";
import { calculateEvidenceCoverage } from "../lib/trust-gap";

interface EvidenceCoverageCardProps {
  report: InvestigationReport;
}

export function EvidenceCoverageCard({ report }: EvidenceCoverageCardProps) {
  const stats = calculateEvidenceCoverage(report);

  const coverageBadgeClass =
    stats.coverageLevel === "Comprehensive"
      ? "badge-match"
      : stats.coverageLevel === "Partial"
      ? "badge-platform"
      : stats.coverageLevel === "Inconclusive"
      ? "badge-unverified"
      : "badge-neutral";

  return (
    <div className="coverage-card" role="region" aria-label="Evidence Coverage and Quality Indicator">
      <div className="coverage-header">
        <div className="coverage-title-group">
          <span className="risk-overline">EVIDENCE COVERAGE & INTEGRITY</span>
          <h4 style={{ margin: "2px 0 0", fontSize: "15px", color: "var(--text-primary)" }}>
            Verification Evidence Scope
          </h4>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span className={`intel-badge ${coverageBadgeClass}`}>
            Coverage: {stats.coverageLevel}
          </span>
          {stats.freshnessDate && (
            <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
              As of {new Date(stats.freshnessDate).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </span>
          )}
        </div>
      </div>

      {/* Quantitative Metrics Row */}
      <div className="coverage-metrics-grid">
        <div className="coverage-stat-box">
          <span className="stat-num" style={{ color: "var(--cyan, #06b6d4)" }}>
            {stats.supportedCount}
          </span>
          <span className="stat-label">Supported Claims</span>
        </div>

        <div className="coverage-stat-box">
          <span
            className="stat-num"
            style={{ color: stats.contradictedCount > 0 ? "var(--danger, #ef4444)" : "var(--text-muted)" }}
          >
            {stats.contradictedCount}
          </span>
          <span className="stat-label">Contradicted Claims</span>
        </div>

        <div className="coverage-stat-box">
          <span
            className="stat-num"
            style={{ color: stats.unverifiedCount > 0 ? "var(--amber, #f59e0b)" : "var(--text-muted)" }}
          >
            {stats.unverifiedCount}
          </span>
          <span className="stat-label">Unverified Gaps</span>
        </div>

        <div className="coverage-stat-box">
          <span className="stat-num" style={{ color: "var(--text-primary)" }}>
            {stats.completedChecksCount}/{stats.totalChecksCount}
          </span>
          <span className="stat-label">Checks Completed</span>
        </div>
      </div>

      {/* Key Findings List */}
      {stats.keyFindings.length > 0 && (
        <div className="coverage-findings-list">
          <span className="coverage-findings-title">Key Coverage Findings:</span>
          <ul>
            {stats.keyFindings.map((finding, idx) => (
              <li key={idx}>{finding}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Grounded Safety Notice */}
      <div className="coverage-disclaimer">
        <span>
          <strong>Verification Notice:</strong> AheadGuard analyzes observable web telemetry and verifiable claims.
          Inconclusive findings must never be treated as safe, and the absence of malicious flags does not constitute an absolute guarantee.
        </span>
      </div>
    </div>
  );
}
