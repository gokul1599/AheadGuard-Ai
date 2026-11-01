"use client";

import { useState, useEffect } from "react";
import { PlatformType, IntegrationStatus, IntegrationCapabilities } from "@/lib/integrations/types";

interface IntegrationSummaryItem {
  platform: PlatformType;
  displayName: string;
  status: IntegrationStatus;
  capabilities: IntegrationCapabilities;
}

export function IntegrationsHub() {
  const [integrations, setIntegrations] = useState<IntegrationSummaryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [activePlatform, setActivePlatform] = useState<IntegrationSummaryItem | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [testStatus, setTestStatus] = useState<Record<string, { ok: boolean; message: string }>>({});

  useEffect(() => {
    fetchIntegrations();
  }, []);

  async function fetchIntegrations() {
    try {
      setLoading(true);
      const res = await fetch("/api/integrations");
      if (res.ok) {
        const data = await res.json();
        setIntegrations(data.integrations || []);
      }
    } catch {
      // Offline fallback
    } finally {
      setLoading(false);
    }
  }

  async function handleToggleConnect(platform: PlatformType, currentStatus: IntegrationStatus) {
    setActionMessage(`Connecting ${platform}...`);
    try {
      const action = currentStatus === "CONNECTED" ? "disconnect" : "connect";
      const res = await fetch("/api/integrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          platform,
          credentials: { simulated: "true" },
        }),
      });
      const data = await res.json();
      if (data.success || data.status) {
        setActionMessage(`${platform} status updated: ${data.status || "COMPLETED"}`);
        await fetchIntegrations();
      } else {
        setActionMessage(`Action failed: ${data.error || data.errorMessage}`);
      }
    } catch {
      setActionMessage(`Error updating ${platform}`);
    }
  }

  async function handleTest(platform: PlatformType) {
    try {
      setTestStatus((prev) => ({ ...prev, [platform]: { ok: true, message: "Testing..." } }));
      const res = await fetch("/api/integrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "test", platform }),
      });
      const data = await res.json();
      setTestStatus((prev) => ({
        ...prev,
        [platform]: { ok: data.ok, message: data.message || "Test completed." },
      }));
    } catch {
      setTestStatus((prev) => ({
        ...prev,
        [platform]: { ok: false, message: "Connection check timed out." },
      }));
    }
  }

  function getStatusBadge(status: IntegrationStatus) {
    switch (status) {
      case "CONNECTED":
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-500/30">CONNECTED</span>;
      case "PERMISSION_LIMITED":
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-amber-950/80 text-amber-400 border border-amber-500/30">SCOPES RESTRICTED</span>;
      case "ACTION_REQUIRED":
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-rose-950/80 text-rose-400 border border-rose-500/30">SETUP REQUIRED</span>;
      case "AVAILABLE":
      case "NOT_CONNECTED":
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-900 text-slate-400 border border-slate-700">NOT CONNECTED</span>;
    }
  }

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono text-sm border border-slate-800 rounded-xl bg-slate-950/60">
        Loading AheadGuard Multi-Platform Integration Registry...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-slate-100 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            Cross-Platform Safety Adapters
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Universal intelligence layer connecting AheadGuard into supported digital communication & social platforms.
          </p>
        </div>
        {actionMessage && (
          <div className="px-3 py-1.5 rounded-lg bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            {actionMessage}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {integrations.map((item) => (
          <div
            key={item.platform}
            className="flex flex-col justify-between p-4 rounded-xl border border-slate-800/80 bg-slate-950/70 hover:border-slate-700 transition"
          >
            <div>
              <div className="flex items-start justify-between gap-2 mb-2">
                <span className="font-medium text-sm text-slate-200 capitalize">{item.platform}</span>
                {getStatusBadge(item.status)}
              </div>
              <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                {item.capabilities.description}
              </p>

              <div className="text-[11px] font-mono text-cyan-400/90 mb-2">
                {item.capabilities.capabilities.filter((c) => c.isAvailable).length} Available Capabilities
              </div>

              {testStatus[item.platform] && (
                <div
                  className={`text-[11px] p-1.5 rounded mb-2 font-mono ${
                    testStatus[item.platform].ok
                      ? "bg-emerald-950/60 text-emerald-300 border border-emerald-500/20"
                      : "bg-rose-950/60 text-rose-300 border border-rose-500/20"
                  }`}
                >
                  {testStatus[item.platform].message}
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800/60 flex items-center gap-2 mt-2">
              <button
                onClick={() => handleToggleConnect(item.platform, item.status)}
                className={`flex-1 text-xs py-1.5 px-2 rounded-lg font-medium transition ${
                  item.status === "CONNECTED"
                    ? "bg-slate-800 hover:bg-slate-700 text-slate-300"
                    : "bg-cyan-600 hover:bg-cyan-500 text-white"
                }`}
              >
                {item.status === "CONNECTED" ? "Disconnect" : "Connect"}
              </button>
              <button
                onClick={() => setActivePlatform(item)}
                className="text-xs py-1.5 px-2.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 transition"
              >
                Details
              </button>
              <button
                onClick={() => handleTest(item.platform)}
                title="Test Connection Health"
                className="text-xs py-1.5 px-2 rounded-lg border border-slate-800 text-slate-400 hover:text-cyan-300 hover:border-slate-700 transition font-mono"
              >
                ⚡
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Details & Honest Limitation Modal */}
      {activePlatform && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="max-w-xl w-full bg-slate-950 border border-slate-700 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                  <span className="capitalize">{activePlatform.platform}</span> Adapter Architecture
                </h3>
                <p className="text-xs text-slate-400">{activePlatform.capabilities.displayName}</p>
              </div>
              <button
                onClick={() => setActivePlatform(null)}
                className="text-slate-400 hover:text-white text-sm font-mono px-2 py-1 rounded"
              >
                ✕ Close
              </button>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-2">
                Supported Capabilities
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {activePlatform.capabilities.capabilities.map((c, idx) => (
                  <li key={idx} className="flex items-start gap-2 bg-slate-900/60 p-2 rounded-lg border border-slate-800/80">
                    <span className="text-emerald-400 mt-0.5">✓</span>
                    <div>
                      <strong className="text-slate-200">{c.name}:</strong> {c.description}
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-rose-400 mb-2">
                Honest Platform Boundaries & Privacy Rules
              </h4>
              <div className="bg-rose-950/30 border border-rose-500/20 rounded-lg p-3 text-xs text-rose-200/90 space-y-2">
                <p>
                  <strong>Policy Boundary:</strong> {activePlatform.capabilities.honestLimitationNotice}
                </p>
                <ul className="list-disc list-inside space-y-1 text-slate-400">
                  {activePlatform.capabilities.unsupportedCapabilities.map((u, idx) => (
                    <li key={idx}>{u}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setActivePlatform(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition"
              >
                Acknowledge & Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
