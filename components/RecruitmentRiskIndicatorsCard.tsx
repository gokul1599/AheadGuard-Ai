"use client";

import React from "react";
import { RecruitmentRiskIndicatorItem } from "@/lib/recruitment-intelligence";

interface RecruitmentRiskIndicatorsCardProps {
  indicators?: RecruitmentRiskIndicatorItem[];
  claimedCompany?: string;
  claimedRole?: string;
  companyStatus?: string;
  jobStatus?: string;
}

export function RecruitmentRiskIndicatorsCard({
  indicators = [],
  claimedCompany,
  claimedRole,
  companyStatus,
  jobStatus,
}: RecruitmentRiskIndicatorsCardProps) {
  // Build a synthesized list ensuring all core indicators are represented
  const rows: Array<{
    indicator: string;
    finding: "Detected" | "Observed" | "Unverified" | "Contradicted" | "Not Detected";
    evidence: string;
    severity: "low" | "medium" | "high" | "severe";
  }> = [];

  // 1. Fee indicator
  const feeInd = indicators.find((i) => i.deduplicationKey === "fee_demand");
  if (feeInd) {
    rows.push({
      indicator: "Upfront recruitment payment",
      finding: "Detected",
      evidence: feeInd.evidence,
      severity: "severe",
    });
  } else {
    rows.push({
      indicator: "Upfront recruitment payment",
      finding: "Not Detected",
      evidence: "No upfront candidate payment requested",
      severity: "low",
    });
  }

  // 2. Payment urgency
  const urgInd = indicators.find((i) => i.deduplicationKey === "payment_urgency");
  if (urgInd) {
    rows.push({
      indicator: "Payment urgency",
      finding: "Detected",
      evidence: urgInd.evidence,
      severity: "high",
    });
  }

  // 3. Selection without interview
  const noIntInd = indicators.find((i) => i.deduplicationKey === "no_interview_process");
  if (noIntInd) {
    rows.push({
      indicator: "Selection without interview",
      finding: "Observed",
      evidence: noIntInd.evidence,
      severity: "high",
    });
  }

  // 4. Offer letter / ID paywall
  const paywallInd = indicators.find((i) => i.deduplicationKey === "doc_paywall");
  if (paywallInd) {
    rows.push({
      indicator: "Credentials/Offer letter paywall",
      finding: "Observed",
      evidence: paywallInd.evidence,
      severity: "severe",
    });
  }

  // 5. Recruiter identity
  const recInd = indicators.find((i) => i.deduplicationKey === "recruiter_channel");
  if (recInd) {
    rows.push({
      indicator: "Recruiter identity",
      finding: "Unverified",
      evidence: recInd.evidence,
      severity: "medium",
    });
  } else {
    rows.push({
      indicator: "Recruiter identity",
      finding: "Unverified",
      evidence: "Independent corporate affiliation not confirmed",
      severity: "medium",
    });
  }

  // 6. Employer identity
  const isCompanyVerified = companyStatus === "Official domain match" || companyStatus === "VERIFIED";
  rows.push({
    indicator: "Employer identity",
    finding: isCompanyVerified ? "Observed" : "Unverified",
    evidence: isCompanyVerified
      ? `Corroborated by corporate records for ${claimedCompany || "employer"}`
      : `No independent corporate confirmation for "${claimedCompany || "claimed employer"}"`,
    severity: isCompanyVerified ? "low" : "medium",
  });

  // 7. Vacancy authenticity
  const isJobVerified = jobStatus === "Listing matched" || jobStatus === "VERIFIED";
  rows.push({
    indicator: "Vacancy authenticity",
    finding: isJobVerified ? "Observed" : "Unverified",
    evidence: isJobVerified
      ? `Listing matched on authenticated careers channel: ${claimedRole || "role"}`
      : `No matching official listing established for "${claimedRole || "claimed role"}"`,
    severity: isJobVerified ? "low" : "medium",
  });

  // 8. Destination domain
  const domInd = indicators.find((i) => i.deduplicationKey === "reserved_example_namespace");
  if (domInd) {
    rows.push({
      indicator: "Destination domain",
      finding: "Observed",
      evidence: domInd.evidence,
      severity: "high",
    });
  }

  return (
    <div className="recruitment-risk-card" style={{
      background: "var(--bg-surface-1, #0f172a)",
      border: "1px solid var(--border-subtle, #1e293b)",
      borderRadius: "14px",
      padding: "20px",
      marginTop: "16px",
      marginBottom: "20px"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
        <div>
          <span style={{ fontSize: "11px", fontFamily: "var(--font-mono, monospace)", color: "#f59e0b", letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 700 }}>
            Structured Threat Intelligence
          </span>
          <h3 style={{ fontSize: "16px", fontWeight: 700, margin: "4px 0 0", color: "#f8fafc" }}>
            RECRUITMENT RISK INDICATORS
          </h3>
        </div>
        <span style={{
          fontSize: "11px",
          fontFamily: "var(--font-mono, monospace)",
          padding: "4px 10px",
          borderRadius: "6px",
          background: "rgba(245, 158, 11, 0.12)",
          color: "#f59e0b",
          border: "1px solid rgba(245, 158, 11, 0.3)"
        }}>
          BEHAVIORAL EVIDENCE LEDGER
        </span>
      </div>

      <p style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "14px", lineHeight: "1.5" }}>
        AheadGuard isolates behavioral warning signs observed in communication independently of external company registration lookups.
      </p>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #334155", color: "#94a3b8", fontFamily: "var(--font-mono, monospace)", fontSize: "11px" }}>
              <th style={{ padding: "8px 12px" }}>INDICATOR</th>
              <th style={{ padding: "8px 12px" }}>FINDING</th>
              <th style={{ padding: "8px 12px" }}>EVIDENCE & CONTEXT</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => {
              const badgeStyle = getFindingBadgeStyle(row.finding);
              return (
                <tr key={idx} style={{ borderBottom: "1px solid rgba(51, 65, 85, 0.5)" }}>
                  <td style={{ padding: "10px 12px", fontWeight: 600, color: "#f1f5f9" }}>
                    {row.indicator}
                  </td>
                  <td style={{ padding: "10px 12px" }}>
                    <span style={badgeStyle}>
                      {row.finding}
                    </span>
                  </td>
                  <td style={{ padding: "10px 12px", color: "#cbd5e1" }}>
                    {row.evidence}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function getFindingBadgeStyle(finding: string): React.CSSProperties {
  switch (finding) {
    case "Detected":
      return {
        background: "rgba(239, 68, 68, 0.15)",
        color: "#f87171",
        border: "1px solid rgba(239, 68, 68, 0.4)",
        padding: "3px 8px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 700,
        fontFamily: "var(--font-mono, monospace)"
      };
    case "Observed":
      return {
        background: "rgba(59, 130, 246, 0.15)",
        color: "#60a5fa",
        border: "1px solid rgba(59, 130, 246, 0.4)",
        padding: "3px 8px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 700,
        fontFamily: "var(--font-mono, monospace)"
      };
    case "Unverified":
      return {
        background: "rgba(245, 158, 11, 0.15)",
        color: "#fbbf24",
        border: "1px solid rgba(245, 158, 11, 0.4)",
        padding: "3px 8px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 700,
        fontFamily: "var(--font-mono, monospace)"
      };
    case "Contradicted":
      return {
        background: "rgba(239, 68, 68, 0.2)",
        color: "#ef4444",
        border: "1px solid #ef4444",
        padding: "3px 8px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 700,
        fontFamily: "var(--font-mono, monospace)"
      };
    default:
      return {
        background: "rgba(148, 163, 184, 0.12)",
        color: "#94a3b8",
        border: "1px solid rgba(148, 163, 184, 0.3)",
        padding: "3px 8px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 600,
        fontFamily: "var(--font-mono, monospace)"
      };
  }
}
