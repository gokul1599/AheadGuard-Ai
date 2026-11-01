"use client";

import { useState } from "react";
import {
  analyzePaymentScreenshot,
  TransactionVerificationReport,
  TransactionSettlementState,
} from "@/lib/transaction-truth/screenshot-forensics";
import { inspectQrPayload, QrInspectionReport } from "@/lib/transaction-truth/qr-inspector";

export function TransactionTruthCard() {
  const [ocrInput, setOcrInput] = useState("");
  const [claimedOrg, setClaimedOrg] = useState("");
  const [qrInput, setQrInput] = useState("");
  const [report, setReport] = useState<TransactionVerificationReport | null>(null);
  const [qrReport, setQrReport] = useState<QrInspectionReport | null>(null);

  function handleAnalyze() {
    if (ocrInput.trim()) {
      const res = analyzePaymentScreenshot({
        ocrText: ocrInput,
        claimedBeneficiary: claimedOrg.trim() || undefined,
      });
      setReport(res);
    }
    if (qrInput.trim()) {
      const qrRes = inspectQrPayload(qrInput);
      setQrReport(qrRes);
    }
  }

  function handleLoadSampleSpoof() {
    setOcrInput(
      "Payment Successful! ₹5,000 paid to Google Cloud Support. UTR: 000000123456. Paytm Spoof Simulator v2.1. Preview only."
    );
    setClaimedOrg("Google");
  }

  function handleLoadSampleQr() {
    setQrInput("upi://pay?pa=refund.desk@okhdfcbank&pn=Instant_Cashback_Refund&am=1500&tn=Electricity_Bill_Refund");
  }

  function getSettlementBadge(state: TransactionSettlementState) {
    switch (state) {
      case "CONFIRMED_SETTLED":
        return <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-500">CONFIRMED SETTLED</span>;
      case "FAILED":
        return <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-rose-950 text-rose-400 border border-rose-500">FAILED / FORGED</span>;
      case "PENDING":
        return <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-amber-950 text-amber-400 border border-amber-500">PENDING IN SWITCH</span>;
      case "UNABLE_TO_VERIFY":
      default:
        return <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-slate-900 text-slate-300 border border-slate-700">UNABLE TO VERIFY SETTLEMENT</span>;
    }
  }

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-semibold tracking-tight text-slate-100 flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
          Transaction Truth — Financial Evidence & Payment Forensics
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Separates easily manipulated payment screenshots from authoritative bank ledger settlements. Detects fake UPI spoof generator APKs and deceptive refund QR traps.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Receipt OCR Input */}
        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/70 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Payment Screenshot / Receipt Text
            </label>
            <button
              onClick={handleLoadSampleSpoof}
              className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline"
            >
              Load Fake Spoof Sample
            </button>
          </div>
          <textarea
            value={ocrInput}
            onChange={(e) => setOcrInput(e.target.value)}
            rows={4}
            placeholder="Paste OCR text from payment screenshot or SMS transaction alert (e.g. 'Paid ₹5,000 to Amazon Recruiter via PhonePe, Ref #...')"
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          />
          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">
              Claimed Business / Beneficiary Name (Optional)
            </label>
            <input
              type="text"
              value={claimedOrg}
              onChange={(e) => setClaimedOrg(e.target.value)}
              placeholder="e.g. Amazon, Google, Scaler"
              className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* QR Code Payload Input */}
        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/70 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-mono uppercase tracking-wider text-slate-300">
              QR Code Payload / Deep Link
            </label>
            <button
              onClick={handleLoadSampleQr}
              className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline"
            >
              Load Fake Refund QR Sample
            </button>
          </div>
          <textarea
            value={qrInput}
            onChange={(e) => setQrInput(e.target.value)}
            rows={4}
            placeholder="Paste scanned QR raw payload (e.g. 'upi://pay?pa=...&pn=...')"
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          />
          <div className="pt-2">
            <button
              onClick={handleAnalyze}
              className="w-full py-2 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition"
            >
              Inspect Payment Evidence & Settle Check
            </button>
          </div>
        </div>
      </div>

      {/* Results Workspace */}
      {report && (
        <div className="p-5 rounded-2xl border border-slate-700 bg-slate-950 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs font-mono text-slate-400">Forensic Receipt Analysis</span>
              <h3 className="text-base font-bold text-slate-100 mt-0.5">
                {report.extracted.platformAppIdentified !== "Unknown"
                  ? `${report.extracted.platformAppIdentified} Receipt`
                  : "Digital Payment Receipt"}
              </h3>
            </div>
            <div>{getSettlementBadge(report.settlementState)}</div>
          </div>

          {/* Honest Notice Banner */}
          <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/30 text-xs text-amber-200/90">
            <strong>Honest Settlement Principle:</strong> {report.honestLimitationNotice}
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400 block text-[10px]">EXTRACTED AMOUNT</span>
              <span className="text-sm font-bold text-slate-100">
                {report.extracted.amount ? `${report.extracted.currency} ${report.extracted.amount}` : "Undetected"}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400 block text-[10px]">BANK UTR / TXN ID</span>
              <span className="text-sm font-bold text-slate-100 truncate block">
                {report.extracted.transactionReference || "None Found"}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400 block text-[10px]">DESTINATION VPA</span>
              <span className="text-sm font-bold text-cyan-300 truncate block">
                {report.extracted.recipientVpa || "None Found"}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400 block text-[10px]">SPOOF APK SIGNAL</span>
              <span
                className={`text-sm font-bold ${
                  report.isSpoofSuspected ? "text-rose-400" : "text-emerald-400"
                }`}
              >
                {report.isSpoofSuspected ? "SUSPECTED" : "CLEAN"}
              </span>
            </div>
          </div>

          {/* Forensic Visual Checks */}
          <div className="space-y-2">
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Automated Forensic Checks ({report.forensicChecks.length})
            </h4>
            <div className="space-y-1.5">
              {report.forensicChecks.map((chk) => (
                <div
                  key={chk.id}
                  className="p-2 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-2 text-xs"
                >
                  <span className={chk.passed ? "text-emerald-400" : "text-rose-400"}>
                    {chk.passed ? "✓" : "⚠"}
                  </span>
                  <div>
                    <strong className="text-slate-200">{chk.name}:</strong>{" "}
                    <span className="text-slate-400">{chk.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Action Recommendation */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs">
            <span className="text-cyan-400 font-semibold uppercase text-[10px] block mb-1">
              Recommended Next Action
            </span>
            <p className="text-slate-200">{report.recommendedAction}</p>
          </div>
        </div>
      )}

      {/* QR Inspection Results */}
      {qrReport && (
        <div className="p-5 rounded-2xl border border-slate-700 bg-slate-950 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs font-mono text-slate-400">QR Code Deep Link Inspection</span>
              <h3 className="text-base font-bold text-slate-100 mt-0.5">
                Scheme: {qrReport.scheme.toUpperCase()}
              </h3>
            </div>
            {qrReport.isCollectRequest && (
              <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-950 text-rose-400 border border-rose-500">
                DEBIT / COLLECT TRAP
              </span>
            )}
          </div>

          {qrReport.warnings.length > 0 && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/30 text-xs text-rose-200 space-y-1">
              <strong>Deceptive QR Indicators Found:</strong>
              <ul className="list-disc list-inside">
                {qrReport.warnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-1">
            <span className="text-cyan-400 font-semibold text-[10px] uppercase block">Safe Action Advice:</span>
            <p className="text-slate-200">{qrReport.safeAction}</p>
          </div>
        </div>
      )}
    </div>
  );
}
