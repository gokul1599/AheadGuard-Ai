"use client";

import React, { useState } from "react";
import { InvestigationReport, ClaimEvaluation } from "../lib/types";
import { buildTrustGraph, TrustNode } from "../lib/trust-gap";

interface TrustGapMapProps {
  report: InvestigationReport;
}

export function TrustGapMap({ report }: TrustGapMapProps) {
  const graph = buildTrustGraph(report);
  const [selectedNodeId, setSelectedNodeId] = useState<string>(
    graph.nodes.find((n) => n.status === "contradicted")?.id || "node-verdict"
  );
  const [filter, setFilter] = useState<ClaimEvaluation | "All">("All");
  const [viewMode, setViewMode] = useState<"visual" | "matrix">("visual");

  const selectedNode = graph.nodes.find((n) => n.id === selectedNodeId) || graph.nodes[0];

  const filteredNodes = graph.nodes.filter((node) => {
    if (filter === "All") return true;
    if (node.type !== "claim") return true; // Keep anchor nodes visible
    if (filter === "Supported") return node.status === "supported";
    if (filter === "Contradicted") return node.status === "contradicted";
    if (filter === "Unverified") return node.status === "unverified";
    return true;
  });

  const getStatusColor = (status: TrustNode["status"]) => {
    switch (status) {
      case "supported":
        return "var(--cyan, #06b6d4)";
      case "contradicted":
        return "var(--danger, #ef4444)";
      case "unverified":
        return "var(--amber, #f59e0b)";
      case "warning":
        return "var(--warning, #f97316)";
      default:
        return "var(--text-muted, #94a3b8)";
    }
  };

  const getStatusBadgeClass = (status: TrustNode["status"]) => {
    switch (status) {
      case "supported":
        return "badge-match";
      case "contradicted":
        return "badge-mismatch";
      case "unverified":
        return "badge-unverified";
      default:
        return "badge-neutral";
    }
  };

  return (
    <div className="trust-gap-container" role="region" aria-label="Trust Gap Map — Claim-to-Evidence Relationship Graph">
      {/* Header & Controls */}
      <div className="trust-gap-header">
        <div>
          <span className="risk-overline">RELATIONSHIP & TRUST GRAPH</span>
          <h4 style={{ margin: "2px 0 0", fontSize: "16px", color: "var(--text-primary)" }}>
            Trust Gap Map
          </h4>
          <p style={{ margin: "4px 0 0", fontSize: "12px", color: "var(--text-secondary)" }}>
            Visualizes verifiable connections between submitted input, claimed identities, observed web infrastructure, claims, and final verdict.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          {/* View Toggle */}
          <div className="claims-filter-group">
            <button
              type="button"
              className={`claims-filter-tab ${viewMode === "visual" ? "active" : ""}`}
              onClick={() => setViewMode("visual")}
            >
              Graph View
            </button>
            <button
              type="button"
              className={`claims-filter-tab ${viewMode === "matrix" ? "active" : ""}`}
              onClick={() => setViewMode("matrix")}
            >
              Matrix Table
            </button>
          </div>

          {/* Filter Pills */}
          <div className="claims-filter-group">
            {(["All", "Supported", "Contradicted", "Unverified"] as const).map((fil) => (
              <button
                key={fil}
                type="button"
                className={`claims-filter-tab ${filter === fil ? "active" : ""}`}
                onClick={() => setFilter(fil)}
              >
                {fil}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Visual Graph View */}
      {viewMode === "visual" && (
        <div className="trust-gap-visual-wrapper">
          {/* Legend */}
          <div className="trust-gap-legend">
            <span className="legend-item">
              <span className="legend-dot" style={{ backgroundColor: "var(--cyan, #06b6d4)" }} />
              Supported / Verified
            </span>
            <span className="legend-item">
              <span className="legend-dot" style={{ backgroundColor: "var(--danger, #ef4444)" }} />
              Contradicted / Mismatch
            </span>
            <span className="legend-item">
              <span className="legend-dot" style={{ backgroundColor: "var(--amber, #f59e0b)" }} />
              Unverified / Gap
            </span>
          </div>

          {/* Interactive Node Graph Grid */}
          <div className="trust-graph-columns">
            {/* Column 1: Submitted Input & Destination */}
            <div className="graph-col">
              <span className="graph-col-title">01 INPUT & INFRASTRUCTURE</span>
              <div className="graph-nodes-stack">
                {filteredNodes
                  .filter((n) => n.type === "input" || n.type === "infrastructure")
                  .map((node) => (
                    <button
                      key={node.id}
                      type="button"
                      onClick={() => setSelectedNodeId(node.id)}
                      className={`graph-node-btn ${selectedNodeId === node.id ? "selected" : ""}`}
                      style={{ borderLeftColor: getStatusColor(node.status) }}
                    >
                      <div className="node-type-label">{node.type.toUpperCase()}</div>
                      <div className="node-main-label">{node.label}</div>
                      {node.sublabel && <div className="node-sub-label">{node.sublabel}</div>}
                    </button>
                  ))}
              </div>
            </div>

            {/* Connecting Arrow */}
            <div className="graph-flow-arrow" aria-hidden="true">
              →
            </div>

            {/* Column 2: Claimed Entity */}
            <div className="graph-col">
              <span className="graph-col-title">02 CLAIMED IDENTITY</span>
              <div className="graph-nodes-stack">
                {filteredNodes
                  .filter((n) => n.type === "entity")
                  .map((node) => (
                    <button
                      key={node.id}
                      type="button"
                      onClick={() => setSelectedNodeId(node.id)}
                      className={`graph-node-btn ${selectedNodeId === node.id ? "selected" : ""}`}
                      style={{ borderLeftColor: getStatusColor(node.status) }}
                    >
                      <div className="node-type-label">{node.type.toUpperCase()}</div>
                      <div className="node-main-label">{node.label}</div>
                      {node.sublabel && <div className="node-sub-label">{node.sublabel}</div>}
                    </button>
                  ))}
              </div>
            </div>

            {/* Connecting Arrow */}
            <div className="graph-flow-arrow" aria-hidden="true">
              →
            </div>

            {/* Column 3: Claims & Evidence Checks */}
            <div className="graph-col flex-2">
              <span className="graph-col-title">03 EVIDENCE & CLAIMS EVALUATION</span>
              <div className="graph-nodes-stack">
                {filteredNodes
                  .filter((n) => n.type === "claim")
                  .map((node) => (
                    <button
                      key={node.id}
                      type="button"
                      onClick={() => setSelectedNodeId(node.id)}
                      className={`graph-node-btn ${selectedNodeId === node.id ? "selected" : ""}`}
                      style={{ borderLeftColor: getStatusColor(node.status) }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span className="node-type-label">{node.type.toUpperCase()}</span>
                        <span className={`intel-badge ${getStatusBadgeClass(node.status)}`} style={{ fontSize: "10px", padding: "1px 6px" }}>
                          {node.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="node-main-label">{node.label}</div>
                      {node.sublabel && <div className="node-sub-label">{node.sublabel}</div>}
                    </button>
                  ))}
                {filteredNodes.filter((n) => n.type === "claim").length === 0 && (
                  <div style={{ fontSize: "12px", color: "var(--text-muted)", padding: "12px" }}>
                    No claims match filter &ldquo;{filter}&rdquo;.
                  </div>
                )}
              </div>
            </div>

            {/* Connecting Arrow */}
            <div className="graph-flow-arrow" aria-hidden="true">
              →
            </div>

            {/* Column 4: Deterministic Verdict */}
            <div className="graph-col">
              <span className="graph-col-title">04 DETERMINISTIC VERDICT</span>
              <div className="graph-nodes-stack">
                {filteredNodes
                  .filter((n) => n.type === "verdict")
                  .map((node) => (
                    <button
                      key={node.id}
                      type="button"
                      onClick={() => setSelectedNodeId(node.id)}
                      className={`graph-node-btn verdict-node ${selectedNodeId === node.id ? "selected" : ""}`}
                      style={{ borderLeftColor: getStatusColor(node.status) }}
                    >
                      <div className="node-type-label">FINAL OUTCOME</div>
                      <div className="node-main-label" style={{ fontWeight: 700 }}>
                        {node.label}
                      </div>
                      {node.sublabel && <div className="node-sub-label">{node.sublabel}</div>}
                    </button>
                  ))}
              </div>
            </div>
          </div>

          {/* Node Inspector Drawer */}
          {selectedNode && (
            <div className="node-inspector-card" role="region" aria-label="Entity Details Inspector">
              <div className="inspector-head">
                <span className="inspector-badge">{selectedNode.type.toUpperCase()} INSPECTION</span>
                <span className={`intel-badge ${getStatusBadgeClass(selectedNode.status)}`}>
                  Status: {selectedNode.status.toUpperCase()}
                </span>
              </div>
              <h5 className="inspector-title">{selectedNode.label}</h5>
              <p className="inspector-details">{selectedNode.details}</p>

              <div className="inspector-meta-grid">
                {selectedNode.sourceUrl && (
                  <div>
                    <span className="meta-field-label">VERIFICATION SOURCE</span>
                    <a
                      href={selectedNode.sourceUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="meta-field-value"
                      style={{ color: "var(--cyan)", display: "inline-block", wordBreak: "break-all" }}
                    >
                      {selectedNode.sourceUrl}
                    </a>
                  </div>
                )}
                {selectedNode.sourceType && (
                  <div>
                    <span className="meta-field-label">SOURCE TYPE</span>
                    <span className="meta-field-value">{selectedNode.sourceType.replace(/_/g, " ")}</span>
                  </div>
                )}
                {selectedNode.retrievedAt && (
                  <div>
                    <span className="meta-field-label">TIMESTAMP</span>
                    <span className="meta-field-value">{selectedNode.retrievedAt}</span>
                  </div>
                )}
                {selectedNode.limitations && (
                  <div>
                    <span className="meta-field-label">LIMITATIONS</span>
                    <span className="meta-field-value" style={{ fontStyle: "italic" }}>
                      {selectedNode.limitations}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Accessible Structured Matrix View */}
      {viewMode === "matrix" && (
        <div className="trust-gap-matrix-wrapper">
          <table className="trust-matrix-table">
            <thead>
              <tr>
                <th scope="col">Entity / Node</th>
                <th scope="col">Type</th>
                <th scope="col">Evidence Status</th>
                <th scope="col">Evaluation & Provenance</th>
                <th scope="col">Source URL / Limitations</th>
              </tr>
            </thead>
            <tbody>
              {filteredNodes.map((n) => (
                <tr key={n.id}>
                  <td>
                    <strong>{n.label}</strong>
                    {n.sublabel && <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>{n.sublabel}</div>}
                  </td>
                  <td>
                    <span className="node-type-label">{n.type}</span>
                  </td>
                  <td>
                    <span className={`intel-badge ${getStatusBadgeClass(n.status)}`} style={{ fontSize: "11px" }}>
                      {n.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{n.details}</td>
                  <td style={{ fontSize: "11px" }}>
                    {n.sourceUrl ? (
                      <a href={n.sourceUrl} target="_blank" rel="noreferrer" style={{ color: "var(--cyan)" }}>
                        Link
                      </a>
                    ) : (
                      <span style={{ color: "var(--text-dim)" }}>Internal / Rule</span>
                    )}
                    {n.limitations && <div style={{ color: "var(--text-dim)", fontStyle: "italic" }}>{n.limitations}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
