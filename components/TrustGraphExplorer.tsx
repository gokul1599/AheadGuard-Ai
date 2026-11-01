"use client";

import { useState, useEffect } from "react";
import { TrustGraphNode, TrustGraphEdge } from "@/lib/trustgraph/graph-store";

export function TrustGraphExplorer() {
  const [nodes, setNodes] = useState<TrustGraphNode[]>([]);
  const [edges, setEdges] = useState<TrustGraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<TrustGraphNode | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchGraph();
  }, []);

  async function fetchGraph() {
    try {
      setLoading(true);
      const res = await fetch("/api/trustgraph");
      if (res.ok) {
        const data = await res.json();
        setNodes(data.nodes || []);
        setEdges(data.edges || []);
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  function getNodeColor(type: string, malicious: boolean) {
    if (malicious) return "bg-rose-950/80 border-rose-500 text-rose-300";
    switch (type) {
      case "UPI_VPA":
        return "bg-amber-950/80 border-amber-500 text-amber-300";
      case "DOMAIN":
        return "bg-cyan-950/80 border-cyan-500 text-cyan-300";
      case "PHONE":
        return "bg-indigo-950/80 border-indigo-500 text-indigo-300";
      case "ORG_ENTITY":
        return "bg-emerald-950/80 border-emerald-500 text-emerald-300";
      default:
        return "bg-slate-900 border-slate-700 text-slate-300";
    }
  }

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono text-sm border border-slate-800 rounded-xl bg-slate-950/60">
        Loading AheadGuard TrustGraph Infrastructure...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-slate-100 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-400 animate-pulse"></span>
            TrustGraph — Cross-Channel Entity Relationship Explorer
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Connects phone numbers, domains, UPI IDs, and brand claims observed across separate messaging and web investigations.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            {nodes.length} Nodes · {edges.length} Edges
          </span>
          <button
            onClick={fetchGraph}
            className="px-3 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-mono transition"
          >
            ↻ Refresh Graph
          </button>
        </div>
      </div>

      {nodes.length === 0 ? (
        <div className="p-12 text-center border border-slate-800/80 rounded-xl bg-slate-950/40 space-y-3">
          <div className="text-3xl">🕸️</div>
          <h3 className="text-sm font-semibold text-slate-300">No Graph Observables Ingested Yet</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Execute investigations across WhatsApp, Instagram, Telegram, or URLs to observe cross-channel entity stitching and campaign clustering in real-time.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Visual Node List / Graph Canvas */}
          <div className="lg:col-span-2 space-y-3 p-4 rounded-xl border border-slate-800/80 bg-slate-950/70">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
              Ingested Graph Entities ({nodes.length})
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[460px] overflow-y-auto pr-2">
              {nodes.map((node) => (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={`p-3 rounded-lg border cursor-pointer transition flex flex-col justify-between ${
                    selectedNode?.id === node.id ? "ring-2 ring-cyan-400" : ""
                  } ${getNodeColor(node.type, node.confirmedMalicious)}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/40 uppercase">
                      {node.type}
                    </span>
                    {node.occurrenceCount > 1 && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {node.occurrenceCount}x Cross-Platform
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-sm font-semibold truncate mt-2">
                    {node.displayValue}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
                    <span>Reputation Risk:</span>
                    <span className="font-mono">
                      {(node.reputationScore * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* Edge relationships preview */}
            <div className="pt-4 border-t border-slate-800/80">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
                Stitched Relationship Edges ({edges.length})
              </h4>
              <div className="space-y-1.5 max-h-36 overflow-y-auto font-mono text-xs text-slate-300">
                {edges.map((edge) => (
                  <div
                    key={edge.id}
                    className="p-1.5 rounded bg-slate-900/60 border border-slate-800/60 flex items-center justify-between"
                  >
                    <span className="text-cyan-400">{edge.relationshipType}</span>
                    <span className="text-slate-500 text-[11px]">Source: {edge.provenanceSource}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Node Inspector Drawer */}
          <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/70 space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Observable Inspector
            </h3>

            {selectedNode ? (
              <div className="space-y-3">
                <div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                    {selectedNode.type}
                  </span>
                  <h4 className="text-base font-mono font-bold text-slate-100 break-all mt-1">
                    {selectedNode.displayValue}
                  </h4>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-slate-400">First Observed:</span>
                    <span className="font-mono text-slate-200">
                      {new Date(selectedNode.firstSeenAt).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Total Observations:</span>
                    <span className="font-mono text-slate-200">{selectedNode.occurrenceCount}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Malicious Flag:</span>
                    <span className={`font-mono ${selectedNode.confirmedMalicious ? "text-rose-400" : "text-emerald-400"}`}>
                      {selectedNode.confirmedMalicious ? "CONFIRMED THREAT" : "UNCONFIRMED"}
                    </span>
                  </div>
                </div>

                <div>
                  <h5 className="text-xs font-semibold text-slate-300 mb-1">Observed Across Channels:</h5>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.associatedPlatforms.map((p, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-500/30 capitalize"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h5 className="text-xs font-semibold text-slate-300 mb-1">Associated Investigations:</h5>
                  <ul className="text-xs font-mono text-slate-400 space-y-1">
                    {selectedNode.associatedInvestigationIds.map((id, idx) => (
                      <li key={idx} className="truncate">
                        • {id}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 py-8 text-center">
                Select any node from the graph to inspect its cross-channel history and provenance evidence.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
