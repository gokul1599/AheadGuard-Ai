"use client";

import { InvestigationReport } from "@/lib/types";

interface SafeActionPlannerProps {
  report: InvestigationReport;
}

export function SafeActionPlannerCard({ report }: SafeActionPlannerProps) {
  const isHighRisk = report.riskOutcome === "High risk";
  const isSuspicious = report.riskOutcome === "Suspicious";

  return (
    <div className="p-5 rounded-2xl border border-slate-700 bg-slate-950 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">Before-You-Act Protocol</span>
          <h3 className="text-base font-bold text-slate-100 mt-0.5">
            Contextual Safe Action Plan
          </h3>
        </div>
        <span
          className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
            isHighRisk
              ? "bg-rose-950 text-rose-400 border border-rose-500"
              : isSuspicious
              ? "bg-amber-950 text-amber-400 border border-amber-500"
              : "bg-emerald-950 text-emerald-400 border border-emerald-500"
          }`}
        >
          {report.riskOutcome.toUpperCase()}
        </span>
      </div>

      <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 text-xs text-slate-200">
        <strong className="text-slate-100 block mb-1">Observable Evidence Summary:</strong>
        {report.outcomeReason}
      </div>

      {/* Action Preview */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <span className="text-[10px] font-mono text-rose-400 uppercase font-semibold block">
            Consequence If You Proceed
          </span>
          <p className="text-slate-300">{report.actionPreview?.consequenceIfProceed || "Financial or credential compromise."}</p>
        </div>

        <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
          <span className="text-[10px] font-mono text-emerald-400 uppercase font-semibold block">
            Safer Deterministic Alternative
          </span>
          <p className="text-slate-300">{report.recommendedAction}</p>
        </div>
      </div>

      {/* Safe Action Checklist */}
      <div className="space-y-2">
        <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
          Immediate Safety Checklist
        </h4>
        <div className="space-y-1.5 text-xs">
          <div className="p-2 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-2">
            <span className="text-rose-400 mt-0.5">✕</span>
            <span className="text-slate-300">
              Never share passwords, 2FA OTP codes, or remote access permissions (AnyDesk / TeamViewer).
            </span>
          </div>
          <div className="p-2 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-2">
            <span className="text-rose-400 mt-0.5">✕</span>
            <span className="text-slate-300">
              Never transfer upfront registration fees, security deposits, or equipment charges for job offers.
            </span>
          </div>
          <div className="p-2 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-2">
            <span className="text-emerald-400 mt-0.5">✓</span>
            <span className="text-slate-300">
              Verify the company directly via their independently located official portal.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
