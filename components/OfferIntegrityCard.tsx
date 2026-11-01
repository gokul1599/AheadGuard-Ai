"use client";

import React, { useState } from "react";
import { OfferIntegrityInput, OfferIntegrityReport } from "../lib/offer-integrity/types";
import { FLAGSHIP_SCENARIO_INPUT } from "../lib/offer-integrity/offer-evaluator";
import { RecruitmentRiskIndicatorsCard } from "./RecruitmentRiskIndicatorsCard";

interface OfferIntegrityCardProps {
  onInvestigateComplete?: (report: OfferIntegrityReport) => void;
}

export function OfferIntegrityCard({ onInvestigateComplete }: OfferIntegrityCardProps) {
  const [formData, setFormData] = useState<OfferIntegrityInput>({
    offerMessage: "",
    claimedCompany: "",
    claimedRole: "",
    recruiterName: "",
    senderEmail: "",
    vacancyUrl: "",
    paymentAmount: "",
    paymentReason: "",
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [report, setReport] = useState<OfferIntegrityReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"breakdown" | "trustgap" | "sources" | "actions">("breakdown");

  const handleLoadFlagship = () => {
    setFormData(FLAGSHIP_SCENARIO_INPUT);
    setError(null);
  };

  const handleReset = () => {
    setFormData({
      offerMessage: "",
      claimedCompany: "",
      claimedRole: "",
      recruiterName: "",
      senderEmail: "",
      vacancyUrl: "",
      paymentAmount: "",
      paymentReason: "",
    });
    setReport(null);
    setError(null);
  };

  const handleInvestigate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.offerMessage.trim()) {
      setError("Please paste the offer message or email text.");
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/offer-integrity", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Offer integrity evaluation failed.");
      }

      setReport(data.report);
      if (onInvestigateComplete) {
        onInvestigateComplete(data.report);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Investigation failed.");
    } finally {
      setIsLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "OBSERVED":
        return <span className="status-badge badge-observed" style={{ background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", border: "1px solid #3b82f6" }}>OBSERVED</span>;
      case "SUPPORTED":
      case "VERIFIED":
      case "VERIFIED_ACTIVE":
      case "LIVE_POLICY_CONFIRMED_NO_FEE":
      case "POLICY_CONFIRMED_NO_FEE":
        return <span className="status-badge badge-match" style={{ background: "rgba(16, 185, 129, 0.15)", color: "#10b981", border: "1px solid #10b981" }}>VERIFIED</span>;
      case "VERIFIED_CLOSED":
      case "VERIFIED_EXPIRED":
        return <span className="status-badge badge-closed" style={{ background: "rgba(245, 158, 11, 0.15)", color: "#f59e0b", border: "1px solid #f59e0b" }}>{status.replace("_", " ")}</span>;
      case "PARTIAL_MATCH":
        return <span className="status-badge badge-partial" style={{ background: "rgba(245, 158, 11, 0.15)", color: "#f59e0b", border: "1px solid #f59e0b" }}>PARTIAL MATCH</span>;
      case "CHECK_FAILED":
        return <span className="status-badge badge-failed" style={{ background: "rgba(239, 68, 68, 0.15)", color: "#ef4444", border: "1px solid #ef4444" }}>CHECK FAILED</span>;
      case "CACHED_POLICY_REFERENCE":
        return <span className="status-badge badge-cached" style={{ background: "rgba(148, 163, 184, 0.15)", color: "#94a3b8", border: "1px solid #94a3b8" }}>CACHED REF</span>;
      case "CONTRADICTED":
        return <span className="status-badge badge-mismatch" style={{ background: "rgba(239, 68, 68, 0.15)", color: "#ef4444", border: "1px solid #ef4444" }}>CONTRADICTED</span>;
      case "UNVERIFIED":
      default:
        return <span className="status-badge badge-unverified" style={{ background: "rgba(245, 158, 11, 0.15)", color: "#f59e0b", border: "1px solid #f59e0b" }}>UNVERIFIED</span>;
    }
  };

  const getRiskOutcomePill = (outcome: string) => {
    if (outcome === "High risk") {
      return <span className="risk-level-badge risk-high" style={{ background: "rgba(239, 68, 68, 0.2)", color: "#ef4444", padding: "6px 14px", borderRadius: "999px", fontWeight: 700, fontSize: "13px", letterSpacing: "0.05em", border: "1px solid #ef4444" }}>HIGH RISK</span>;
    }
    if (outcome === "Suspicious") {
      return <span className="risk-level-badge risk-suspicious" style={{ background: "rgba(245, 158, 11, 0.2)", color: "#f59e0b", padding: "6px 14px", borderRadius: "999px", fontWeight: 700, fontSize: "13px", letterSpacing: "0.05em", border: "1px solid #f59e0b" }}>SUSPICIOUS</span>;
    }
    if (outcome === "Unknown") {
      return <span className="risk-level-badge risk-unknown" style={{ background: "rgba(148, 163, 184, 0.2)", color: "#94a3b8", padding: "6px 14px", borderRadius: "999px", fontWeight: 700, fontSize: "13px", letterSpacing: "0.05em", border: "1px solid #94a3b8" }}>UNKNOWN</span>;
    }
    return <span className="risk-level-badge risk-low" style={{ background: "rgba(16, 185, 129, 0.2)", color: "#10b981", padding: "6px 14px", borderRadius: "999px", fontWeight: 700, fontSize: "13px", letterSpacing: "0.05em", border: "1px solid #10b981" }}>LOW OBSERVED RISK</span>;
  };

  return (
    <div className="offer-integrity-card" style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Header Banner */}
      <div className="card-header" style={{ borderBottom: "1px solid var(--border-subtle, #1e293b)", paddingBottom: "16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span className="risk-overline" style={{ color: "#06b6d4", fontSize: "11px", fontWeight: 700, letterSpacing: "0.1em" }}>
                OFFER INTEGRITY INTELLIGENCE 2.1
              </span>
              <span style={{ fontSize: "11px", padding: "2px 8px", background: "rgba(6, 182, 212, 0.12)", color: "#06b6d4", borderRadius: "4px", border: "1px solid rgba(6, 182, 212, 0.3)" }}>
                BEFORE-YOU-PAY GUARDIAN
              </span>
            </div>
            <h2 style={{ fontSize: "20px", fontWeight: 700, margin: "6px 0 2px", color: "var(--text-primary, #f8fafc)" }}>
              Check an Internship or Job Offer Before You Pay
            </h2>
            <p style={{ fontSize: "13px", color: "var(--text-secondary, #94a3b8)", margin: 0 }}>
              Investigate whether the role, recruiter affiliation, and payment demand can be verified independently against official corporate policies.
            </p>
          </div>

          <button
            type="button"
            onClick={handleLoadFlagship}
            className="secondary-btn"
            style={{
              padding: "8px 16px",
              fontSize: "12px",
              fontWeight: 600,
              borderRadius: "6px",
              background: "rgba(6, 182, 212, 0.1)",
              border: "1px solid #06b6d4",
              color: "#06b6d4",
              cursor: "pointer",
              transition: "all 0.2s ease",
            }}
          >
            ⚡ Load Flagship Scenario (₹999 AI Internship Scam)
          </button>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleInvestigate} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
        <div>
          <label style={{ display: "block", fontSize: "13px", fontWeight: 600, color: "var(--text-primary, #f8fafc)", marginBottom: "6px" }}>
            Paste Offer Message, Email, or WhatsApp Communication *
          </label>
          <textarea
            value={formData.offerMessage}
            onChange={(e) => setFormData({ ...formData, offerMessage: e.target.value })}
            placeholder='e.g., "Congratulations! You have been shortlisted for an internship in our AI department. Your role is listed on our careers portal. Pay ₹999 to reserve your interview slot via UPI..."'
            rows={4}
            style={{
              width: "100%",
              padding: "12px",
              borderRadius: "8px",
              background: "var(--bg-input, #0b1329)",
              border: "1px solid var(--border-subtle, #1e293b)",
              color: "var(--text-primary, #f8fafc)",
              fontSize: "13px",
              fontFamily: "inherit",
              resize: "vertical",
            }}
          />
        </div>

        {/* Optional Structured Fields */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" }}>
          <div>
            <label style={{ display: "block", fontSize: "12px", color: "var(--text-secondary, #94a3b8)", marginBottom: "4px" }}>
              Claimed Company (optional)
            </label>
            <input
              type="text"
              placeholder="e.g., Google, Microsoft, TCS"
              value={formData.claimedCompany}
              onChange={(e) => setFormData({ ...formData, claimedCompany: e.target.value })}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "6px",
                background: "var(--bg-input, #0b1329)",
                border: "1px solid var(--border-subtle, #1e293b)",
                color: "var(--text-primary, #f8fafc)",
                fontSize: "12px",
              }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12px", color: "var(--text-secondary, #94a3b8)", marginBottom: "4px" }}>
              Internship or Job Title (optional)
            </label>
            <input
              type="text"
              placeholder="e.g., AI Intern, Software Engineer"
              value={formData.claimedRole}
              onChange={(e) => setFormData({ ...formData, claimedRole: e.target.value })}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "6px",
                background: "var(--bg-input, #0b1329)",
                border: "1px solid var(--border-subtle, #1e293b)",
                color: "var(--text-primary, #f8fafc)",
                fontSize: "12px",
              }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12px", color: "var(--text-secondary, #94a3b8)", marginBottom: "4px" }}>
              Sender Email / Contact (optional)
            </label>
            <input
              type="text"
              placeholder="e.g., recruiter@gmail.com"
              value={formData.senderEmail}
              onChange={(e) => setFormData({ ...formData, senderEmail: e.target.value })}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "6px",
                background: "var(--bg-input, #0b1329)",
                border: "1px solid var(--border-subtle, #1e293b)",
                color: "var(--text-primary, #f8fafc)",
                fontSize: "12px",
              }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12px", color: "var(--text-secondary, #94a3b8)", marginBottom: "4px" }}>
              Fee Requested (optional)
            </label>
            <input
              type="text"
              placeholder="e.g., 999 INR, $500"
              value={formData.paymentAmount}
              onChange={(e) => setFormData({ ...formData, paymentAmount: e.target.value })}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "6px",
                background: "var(--bg-input, #0b1329)",
                border: "1px solid var(--border-subtle, #1e293b)",
                color: "var(--text-primary, #f8fafc)",
                fontSize: "12px",
              }}
            />
          </div>
        </div>

        {/* Privacy notice & Action buttons */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
          <div style={{ fontSize: "12px", color: "var(--text-secondary, #94a3b8)" }}>
            🔒 <strong style={{ color: "#38bdf8" }}>Privacy Notice:</strong> Analyzes public corporate web claims. Never paste passwords, banking PINs, or Aadhaar/Govt ID documents.
          </div>

          <div style={{ display: "flex", gap: "10px" }}>
            {formData.offerMessage && (
              <button
                type="button"
                onClick={handleReset}
                className="secondary-btn"
                style={{
                  padding: "10px 18px",
                  fontSize: "13px",
                  borderRadius: "6px",
                  background: "transparent",
                  border: "1px solid var(--border-subtle, #1e293b)",
                  color: "var(--text-secondary, #94a3b8)",
                  cursor: "pointer",
                }}
              >
                Clear
              </button>
            )}

            <button
              type="submit"
              disabled={isLoading}
              style={{
                padding: "10px 24px",
                fontSize: "13px",
                fontWeight: 700,
                borderRadius: "6px",
                background: "linear-gradient(135deg, #0284c7 0%, #06b6d4 100%)",
                border: "none",
                color: "#ffffff",
                cursor: isLoading ? "not-allowed" : "pointer",
                boxShadow: "0 4px 14px rgba(6, 182, 212, 0.3)",
              }}
            >
              {isLoading ? "Investigating Claims..." : "🛡️ Investigate Offer Integrity"}
            </button>
          </div>
        </div>
      </form>

      {error && (
        <div style={{ padding: "12px 16px", borderRadius: "6px", background: "rgba(239, 68, 68, 0.1)", border: "1px solid #ef4444", color: "#fca5a5", fontSize: "13px" }}>
          ⚠️ {error}
        </div>
      )}

      {/* Investigation Results Report */}
      {report && (
        <div className="offer-integrity-results" style={{ marginTop: "16px", display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Section 1: Overall Assessment & Core Distinction Banner */}
          <div
            className="assessment-box"
            style={{
              padding: "20px",
              borderRadius: "10px",
              background: report.riskOutcome === "High risk" ? "rgba(239, 68, 68, 0.08)" : "rgba(6, 182, 212, 0.06)",
              border: `1px solid ${report.riskOutcome === "High risk" ? "#ef4444" : "#06b6d4"}`,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px", marginBottom: "12px" }}>
              <div>
                <span style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.1em", color: "var(--text-secondary, #94a3b8)" }}>
                  INVESTIGATION OUTCOME
                </span>
                <h3 style={{ fontSize: "18px", fontWeight: 700, margin: "4px 0", color: "var(--text-primary, #f8fafc)" }}>
                  {report.overallAssessment.verdictTitle}
                </h3>
              </div>
              {getRiskOutcomePill(report.riskOutcome)}
            </div>

            {/* TinyFish Live Research Indicator */}
            {report.tinyFishResearchOutcome?.invoked && (
              <div
                style={{
                  padding: "10px 14px",
                  borderRadius: "6px",
                  background: "rgba(6, 182, 212, 0.1)",
                  border: "1px solid #06b6d4",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  fontSize: "12px",
                  marginBottom: "14px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#38bdf8", fontWeight: 600 }}>
                  <span>🐟</span>
                  <span>TinyFish Live Web Research Completed</span>
                  <span style={{ fontSize: "11px", padding: "2px 6px", borderRadius: "4px", background: "rgba(6, 182, 212, 0.2)" }}>
                    {report.tinyFishResearchOutcome.eventsCount} events
                  </span>
                </div>
                <span style={{ color: "#94a3b8", fontSize: "11px" }}>
                  Verified via isolated live browser session
                </span>
              </div>
            )}

            {/* Core Principle Callout */}
            <div
              style={{
                padding: "12px 16px",
                borderRadius: "8px",
                background: "rgba(15, 23, 42, 0.7)",
                borderLeft: "4px solid #06b6d4",
                marginBottom: "14px",
              }}
            >
              <div style={{ fontSize: "13px", fontWeight: 700, color: "#38bdf8", marginBottom: "2px" }}>
                🎯 CORE TRUST PRINCIPLE
              </div>
              <p style={{ fontSize: "13px", color: "var(--text-primary, #f8fafc)", margin: 0, lineHeight: 1.5 }}>
                {report.coreDistinctionNotice}
              </p>
            </div>

            <p style={{ fontSize: "13px", color: "var(--text-secondary, #cbd5e1)", lineHeight: 1.6, margin: "0 0 14px" }}>
              {report.overallAssessment.verdictSummary}
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px", fontSize: "12px" }}>
              <div style={{ background: "rgba(11, 19, 41, 0.6)", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-subtle, #1e293b)" }}>
                <span style={{ color: "#38bdf8", fontWeight: 600 }}>Strongest Evidence:</span>
                <div style={{ color: "var(--text-primary, #f8fafc)", marginTop: "3px" }}>{report.overallAssessment.strongestEvidence}</div>
              </div>

              <div style={{ background: "rgba(11, 19, 41, 0.6)", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--border-subtle, #1e293b)" }}>
                <span style={{ color: "#ef4444", fontWeight: 600 }}>Most Consequential Finding:</span>
                <div style={{ color: "var(--text-primary, #f8fafc)", marginTop: "3px" }}>{report.overallAssessment.mostConsequentialFinding}</div>
              </div>
            </div>

            <div style={{ marginTop: "14px", padding: "10px 14px", background: "rgba(239, 68, 68, 0.15)", borderRadius: "6px", border: "1px solid rgba(239, 68, 68, 0.4)", color: "#fca5a5", fontSize: "13px", fontWeight: 600 }}>
              🛑 Recommended Action: {report.overallAssessment.recommendedAction}
            </div>
          </div>

          {/* Structured Recruitment Risk Indicators */}
          {report.recruitmentIndicators && report.recruitmentIndicators.length > 0 && (
            <RecruitmentRiskIndicatorsCard
              indicators={report.recruitmentIndicators}
              claimedCompany={report.input.claimedCompany}
              claimedRole={report.input.claimedRole}
            />
          )}

          {/* Canonical Extraction Summary Box */}
          {report.canonicalExtraction && (
            <div
              style={{
                padding: "16px 20px",
                borderRadius: "8px",
                background: "rgba(15, 23, 42, 0.7)",
                border: "1px solid var(--border-subtle, #1e293b)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", borderBottom: "1px solid rgba(30, 41, 59, 0.5)", paddingBottom: "8px" }}>
                <span style={{ fontSize: "12px", fontWeight: 700, color: "#38bdf8", letterSpacing: "0.08em" }}>
                  📋 EXTRACTED OFFER CLAIMS (PRE-VERIFICATION BASELINE)
                </span>
                <span style={{ fontSize: "11px", color: "var(--text-secondary, #94a3b8)" }}>
                  Extracted from submitted communication
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px", fontSize: "12px" }}>
                <div>
                  <span style={{ color: "#94a3b8", display: "block" }}>Claimed Employer</span>
                  <strong style={{ color: "#f8fafc" }}>{report.canonicalExtraction.employer.name}</strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8", display: "block" }}>Position / Requisition</span>
                  <strong style={{ color: "#f8fafc" }}>
                    {report.canonicalExtraction.job.title}
                    {report.canonicalExtraction.job.duration ? ` • ${report.canonicalExtraction.job.duration}` : ""}
                    {report.canonicalExtraction.job.workMode ? ` • ${report.canonicalExtraction.job.workMode}` : ""}
                  </strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8", display: "block" }}>Compensation</span>
                  <strong style={{ color: report.canonicalExtraction.compensation.disclosedInMessage ? "#10b981" : "#94a3b8" }}>
                    {report.canonicalExtraction.compensation.disclosedInMessage
                      ? `${report.canonicalExtraction.compensation.amountString || report.canonicalExtraction.compensation.amount} (${report.canonicalExtraction.compensation.period})`
                      : "Not disclosed in message/listing"}
                  </strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8", display: "block" }}>Recruiter Identity</span>
                  <strong style={{ color: "#f8fafc" }}>
                    {report.canonicalExtraction.recruiter.name || "Could not extract this field — manual review required"}
                    {report.canonicalExtraction.recruiter.designation ? ` (${report.canonicalExtraction.recruiter.designation})` : ""}
                    {report.canonicalExtraction.recruiter.handle ? ` via ${report.canonicalExtraction.recruiter.channel}: ${report.canonicalExtraction.recruiter.handle}` : ""}
                  </strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8", display: "block" }}>Payment Demand</span>
                  <strong style={{ color: report.canonicalExtraction.payment.requested ? "#ef4444" : "#10b981" }}>
                    {report.canonicalExtraction.payment.requested
                      ? `${report.canonicalExtraction.payment.amountString && report.canonicalExtraction.payment.amountString !== "Undisclosed" ? `${report.canonicalExtraction.payment.currency || "INR"} ${report.canonicalExtraction.payment.amountString}` : "Mandatory fee demanded (amount undisclosed)"}${report.canonicalExtraction.payment.upiId ? ` via UPI (${report.canonicalExtraction.payment.upiId})` : ""}${report.canonicalExtraction.payment.deadline ? ` [Deadline: ${report.canonicalExtraction.payment.deadline}]` : ""}`
                      : "No fees requested in communication"}
                  </strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8", display: "block" }}>Selection Conditions</span>
                  <strong style={{ color: "#f8fafc" }}>
                    {report.canonicalExtraction.selection.interviewRequired ? "Interview required" : "No interview required"}
                    {report.canonicalExtraction.selection.paymentRequiredForOfferLetter ? " • Offer letter paywalled" : ""}
                  </strong>
                </div>
              </div>
            </div>
          )}

          {/* Navigation Tabs for Details */}
          <div style={{ display: "flex", gap: "8px", borderBottom: "1px solid var(--border-subtle, #1e293b)", paddingBottom: "8px" }}>
            <button
              type="button"
              onClick={() => setActiveTab("breakdown")}
              style={{
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 600,
                borderRadius: "6px",
                background: activeTab === "breakdown" ? "rgba(6, 182, 212, 0.15)" : "transparent",
                color: activeTab === "breakdown" ? "#06b6d4" : "var(--text-secondary, #94a3b8)",
                border: activeTab === "breakdown" ? "1px solid #06b6d4" : "1px solid transparent",
                cursor: "pointer",
              }}
            >
              Component Breakdown
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("trustgap")}
              style={{
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 600,
                borderRadius: "6px",
                background: activeTab === "trustgap" ? "rgba(6, 182, 212, 0.15)" : "transparent",
                color: activeTab === "trustgap" ? "#06b6d4" : "var(--text-secondary, #94a3b8)",
                border: activeTab === "trustgap" ? "1px solid #06b6d4" : "1px solid transparent",
                cursor: "pointer",
              }}
            >
              Trust Gap Ledger ({report.claimsLedger.length} Claims)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("sources")}
              style={{
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 600,
                borderRadius: "6px",
                background: activeTab === "sources" ? "rgba(6, 182, 212, 0.15)" : "transparent",
                color: activeTab === "sources" ? "#06b6d4" : "var(--text-secondary, #94a3b8)",
                border: activeTab === "sources" ? "1px solid #06b6d4" : "1px solid transparent",
                cursor: "pointer",
              }}
            >
              Source Explorer ({report.sourceExplorer.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("actions")}
              style={{
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 600,
                borderRadius: "6px",
                background: activeTab === "actions" ? "rgba(6, 182, 212, 0.15)" : "transparent",
                color: activeTab === "actions" ? "#06b6d4" : "var(--text-secondary, #94a3b8)",
                border: activeTab === "actions" ? "1px solid #06b6d4" : "1px solid transparent",
                cursor: "pointer",
              }}
            >
              Safe Action Plan
            </button>
          </div>

          {/* Tab 1: Component Breakdown */}
          {activeTab === "breakdown" && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "14px" }}>
              {/* Card 1: Internship Vacancy */}
              <div style={{ padding: "14px", borderRadius: "8px", background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle, #1e293b)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-secondary, #94a3b8)" }}>1. VACANCY REQUISITION</span>
                  {getStatusBadge(report.offerBreakdown.vacancy.vacancyStatus)}
                </div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary, #f8fafc)", marginBottom: "4px" }}>
                  {report.offerBreakdown.vacancy.roleTitle}
                </div>
                <p style={{ fontSize: "12px", color: "var(--text-secondary, #94a3b8)", margin: "0 0 10px", lineHeight: 1.5 }}>
                  {report.offerBreakdown.vacancy.explanation}
                </p>
                {report.offerBreakdown.vacancy.matchedListingUrl && (
                  <a
                    href={report.offerBreakdown.vacancy.matchedListingUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontSize: "11px", color: "#38bdf8", textDecoration: "underline" }}
                  >
                    🔗 View verified official listing on {report.offerBreakdown.vacancy.officialDomain}
                  </a>
                )}
              </div>

              {/* Card 2: Payment Request */}
              <div style={{ padding: "14px", borderRadius: "8px", background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle, #1e293b)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-secondary, #94a3b8)" }}>2. PAYMENT REQUIREMENT</span>
                  {getStatusBadge(report.offerBreakdown.payment.paymentStatus)}
                </div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: report.offerBreakdown.payment.conflictsWithPolicy ? "#ef4444" : "var(--text-primary, #f8fafc)", marginBottom: "4px" }}>
                  {report.offerBreakdown.payment.paymentRequested
                    ? report.offerBreakdown.payment.amount
                      ? `${report.offerBreakdown.payment.currency || "INR"} ${report.offerBreakdown.payment.amount} (${report.offerBreakdown.payment.statedReason || "Recruitment fee"})`
                      : "Mandatory recruitment fee (amount undisclosed in communication)"
                    : "No Fees Detected in Message"}
                </div>
                <p style={{ fontSize: "12px", color: "var(--text-secondary, #94a3b8)", margin: "0 0 10px", lineHeight: 1.5 }}>
                  {report.offerBreakdown.payment.explanation}
                </p>
                {report.offerBreakdown.policy.policyQuote && (
                  <div style={{ fontSize: "11px", padding: "8px", background: "rgba(239, 68, 68, 0.1)", borderRadius: "4px", color: "#fca5a5", borderLeft: "2px solid #ef4444" }}>
                    &ldquo;{report.offerBreakdown.policy.policyQuote}&rdquo;
                  </div>
                )}
              </div>

              {/* Card 3: Recruiter Affiliation & Verification Dimensions */}
              <div style={{ padding: "14px", borderRadius: "8px", background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle, #1e293b)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-secondary, #94a3b8)" }}>3. SENDER & RECRUITER AFFILIATION</span>
                  {getStatusBadge(report.offerBreakdown.sender.affiliationStatus)}
                </div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary, #f8fafc)", marginBottom: "4px" }}>
                  {report.offerBreakdown.sender.claimedRecruiterName || "Could not extract this field — manual review required"}
                  {report.offerBreakdown.sender.claimedDesignation && ` • ${report.offerBreakdown.sender.claimedDesignation}`}
                  {report.offerBreakdown.sender.senderEmail && ` (${report.offerBreakdown.sender.senderEmail})`}
                </div>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", margin: "6px 0 10px", fontSize: "11px" }}>
                  <span style={{ padding: "2px 8px", borderRadius: "4px", background: "rgba(148, 163, 184, 0.12)", color: "#cbd5e1", border: "1px solid rgba(148, 163, 184, 0.25)" }}>
                    Channel: {report.offerBreakdown.sender.communicationChannel || "Unspecified"}
                  </span>
                  <span style={{ padding: "2px 8px", borderRadius: "4px", background: report.offerBreakdown.sender.emailDomainMatchesCompany ? "rgba(16, 185, 129, 0.12)" : "rgba(245, 158, 11, 0.12)", color: report.offerBreakdown.sender.emailDomainMatchesCompany ? "#10b981" : "#f59e0b", border: `1px solid ${report.offerBreakdown.sender.emailDomainMatchesCompany ? "#10b981" : "#f59e0b"}` }}>
                    Domain: {report.offerBreakdown.sender.emailDomainConsistency || (report.offerBreakdown.sender.emailDomainMatchesCompany ? "MATCHED_DOMAIN" : "UNVERIFIED")}
                  </span>
                  <span style={{ padding: "2px 8px", borderRadius: "4px", background: "rgba(245, 158, 11, 0.12)", color: "#f59e0b", border: "1px solid #f59e0b" }}>
                    Identity: {report.offerBreakdown.sender.individualIdentityStatus || "UNVERIFIED"}
                  </span>
                </div>
                <p style={{ fontSize: "12px", color: "var(--text-secondary, #94a3b8)", margin: "0 0 6px", lineHeight: 1.5 }}>
                  {report.offerBreakdown.sender.explanation}
                </p>
                {report.offerBreakdown.sender.emailDomainMatchesCompany && (
                  <div style={{ fontSize: "11px", padding: "6px 8px", background: "rgba(59, 130, 246, 0.08)", borderRadius: "4px", color: "#93c5fd", borderLeft: "2px solid #3b82f6" }}>
                    ℹ️ Corporate email-domain consistency observed; individual recruiter identity and authorization remain independently unverified.
                  </div>
                )}
              </div>

              {/* Card 4: Application Portal */}
              <div style={{ padding: "14px", borderRadius: "8px", background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle, #1e293b)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-secondary, #94a3b8)" }}>4. APPLICATION PORTAL</span>
                  {getStatusBadge(report.offerBreakdown.destination.isDomainConsistent ? "SUPPORTED" : "UNVERIFIED")}
                </div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text-primary, #f8fafc)", marginBottom: "4px" }}>
                  {report.offerBreakdown.destination.destinationType}
                </div>
                <p style={{ fontSize: "12px", color: "var(--text-secondary, #94a3b8)", margin: 0, lineHeight: 1.5 }}>
                  {report.offerBreakdown.destination.explanation}
                </p>
              </div>
            </div>
          )}

          {/* Tab 2: Trust Gap Map Table */}
          {activeTab === "trustgap" && (
            <div style={{ overflowX: "auto", borderRadius: "8px", border: "1px solid var(--border-subtle, #1e293b)" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
                <thead>
                  <tr style={{ background: "rgba(15, 23, 42, 0.8)", borderBottom: "1px solid var(--border-subtle, #1e293b)" }}>
                    <th style={{ padding: "10px 14px", color: "var(--text-secondary, #94a3b8)" }}>Claim Category</th>
                    <th style={{ padding: "10px 14px", color: "var(--text-secondary, #94a3b8)" }}>Extracted Content</th>
                    <th style={{ padding: "10px 14px", color: "var(--text-secondary, #94a3b8)" }}>Status</th>
                    <th style={{ padding: "10px 14px", color: "var(--text-secondary, #94a3b8)" }}>Evidence & Reason</th>
                    <th style={{ padding: "10px 14px", color: "var(--text-secondary, #94a3b8)" }}>Suggested Action</th>
                  </tr>
                </thead>
                <tbody>
                  {report.claimsLedger.map((claim) => (
                    <tr key={claim.id} style={{ borderBottom: "1px solid rgba(30, 41, 59, 0.6)" }}>
                      <td style={{ padding: "12px 14px", fontWeight: 600, color: "var(--text-primary, #f8fafc)" }}>
                        {claim.claimTitle}
                      </td>
                      <td style={{ padding: "12px 14px", color: "var(--text-secondary, #cbd5e1)", maxWidth: "200px" }}>
                        {claim.extractedValue}
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        {getStatusBadge(claim.status)}
                      </td>
                      <td style={{ padding: "12px 14px", color: "var(--text-secondary, #94a3b8)", maxWidth: "260px", lineHeight: 1.4 }}>
                        {claim.explanation}
                      </td>
                      <td style={{ padding: "12px 14px", color: "#38bdf8", maxWidth: "220px", lineHeight: 1.4 }}>
                        {claim.suggestedAction}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Tab 3: Source Explorer */}
          {activeTab === "sources" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {report.sourceExplorer.map((source, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: "12px 16px",
                    borderRadius: "8px",
                    background: "rgba(15, 23, 42, 0.6)",
                    border: "1px solid var(--border-subtle, #1e293b)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: "10px",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-primary, #f8fafc)" }}>
                        {source.title}
                      </span>
                      <span style={{ fontSize: "11px", padding: "1px 6px", background: "rgba(56, 189, 248, 0.1)", color: "#38bdf8", borderRadius: "4px" }}>
                        {source.authorityLevel}
                      </span>
                    </div>
                    <div style={{ fontSize: "12px", color: "var(--text-secondary, #94a3b8)", marginTop: "2px" }}>
                      {source.relevantFinding}
                    </div>
                    <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                      Domain: {source.domain} • Observed: {new Date(source.observationTime).toLocaleTimeString()}
                    </div>
                  </div>

                  <a
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      padding: "6px 12px",
                      borderRadius: "6px",
                      background: "rgba(6, 182, 212, 0.1)",
                      border: "1px solid #06b6d4",
                      color: "#06b6d4",
                      fontSize: "12px",
                      fontWeight: 600,
                      textDecoration: "none",
                    }}
                  >
                    Open Source ↗
                  </a>
                </div>
              ))}
            </div>
          )}

          {/* Tab 4: Safe Action Plan */}
          {activeTab === "actions" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {/* Primary Warning */}
              <div style={{ padding: "14px 18px", borderRadius: "8px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", color: "#fca5a5" }}>
                <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "4px" }}>⚠️ MANDATORY SAFETY DIRECTIVE</div>
                <div style={{ fontSize: "14px", fontWeight: 600 }}>{report.safeActionPlan.primaryWarning}</div>
              </div>

              {/* Verified Application Route */}
              {report.safeActionPlan.verifiedApplicationRoute && (
                <div style={{ padding: "14px 18px", borderRadius: "8px", background: "rgba(6, 182, 212, 0.1)", border: "1px solid #06b6d4" }}>
                  <div style={{ fontSize: "12px", fontWeight: 700, color: "#06b6d4", marginBottom: "4px" }}>
                    ✅ AUTHENTIC RECRUITMENT PATHWAY
                  </div>
                  <div style={{ fontSize: "13px", color: "var(--text-primary, #f8fafc)", marginBottom: "8px" }}>
                    Skip the unverified recruiter and apply directly through the employer&apos;s verified public portal:
                  </div>
                  <a
                    href={report.safeActionPlan.verifiedApplicationRoute}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: "inline-block",
                      padding: "8px 16px",
                      borderRadius: "6px",
                      background: "#06b6d4",
                      color: "#040812",
                      fontSize: "12px",
                      fontWeight: 700,
                      textDecoration: "none",
                    }}
                  >
                    Open Verified Corporate Careers Page ↗
                  </a>
                </div>
              )}

              {/* Steps Checklist */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "14px" }}>
                <div style={{ padding: "14px", borderRadius: "8px", background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle, #1e293b)" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: 700, color: "#10b981", margin: "0 0 10px" }}>
                    Recommended Next Steps
                  </h4>
                  <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "12px", color: "var(--text-secondary, #cbd5e1)", lineHeight: 1.6 }}>
                    {report.safeActionPlan.stepByStepActions.map((step, i) => (
                      <li key={i} style={{ marginBottom: "6px" }}>{step}</li>
                    ))}
                  </ul>
                </div>

                <div style={{ padding: "14px", borderRadius: "8px", background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle, #1e293b)" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: 700, color: "#ef4444", margin: "0 0 10px" }}>
                    What NOT To Do
                  </h4>
                  <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "12px", color: "var(--text-secondary, #cbd5e1)", lineHeight: 1.6 }}>
                    {report.safeActionPlan.whatNotToDo.map((step, i) => (
                      <li key={i} style={{ marginBottom: "6px" }}>{step}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
