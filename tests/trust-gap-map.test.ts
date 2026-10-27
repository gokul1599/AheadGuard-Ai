import { describe, it, expect } from "vitest";
import { buildTrustGraph } from "../lib/trust-gap";
import { DEMO_SCENARIO_A, DEMO_SCENARIO_B, DEMO_SCENARIO_C } from "../lib/demo-data";
import { InvestigationReport } from "../lib/types";

describe("Trust Gap Map — Relationship Graph Derivation", () => {
  it("builds a connected graph for Scenario A (Supported claims)", () => {
    const graph = buildTrustGraph(DEMO_SCENARIO_A);

    expect(graph.nodes.length).toBeGreaterThanOrEqual(5);
    expect(graph.edges.length).toBeGreaterThanOrEqual(4);

    const inputNode = graph.nodes.find((n) => n.id === "node-input");
    const entityNode = graph.nodes.find((n) => n.id === "node-entity");
    const infraNode = graph.nodes.find((n) => n.id === "node-infra");
    const verdictNode = graph.nodes.find((n) => n.id === "node-verdict");

    expect(inputNode).toBeDefined();
    expect(entityNode?.status).toBe("supported");
    expect(infraNode?.label).toContain("acme-cloud.tech");
    expect(verdictNode?.label).toBe("Low observed risk");
    expect(verdictNode?.status).toBe("supported");

    // All claims for Scenario A should be supported
    const claimNodes = graph.nodes.filter((n) => n.type === "claim");
    expect(claimNodes.length).toBe(DEMO_SCENARIO_A.scamIntelligence!.claims.length);
    expect(claimNodes.every((c) => c.status === "supported")).toBe(true);
  });

  it("builds a graph identifying contradictions for Scenario B (Fee trap / lookalike)", () => {
    const graph = buildTrustGraph(DEMO_SCENARIO_B);

    const entityNode = graph.nodes.find((n) => n.id === "node-entity");
    expect(entityNode?.status).toBe("contradicted");

    const verdictNode = graph.nodes.find((n) => n.id === "node-verdict");
    expect(verdictNode?.label).toBe("High risk");
    expect(verdictNode?.status).toBe("contradicted");

    const contradictedClaims = graph.nodes.filter((n) => n.type === "claim" && n.status === "contradicted");
    expect(contradictedClaims.length).toBeGreaterThanOrEqual(2);

    // Edges with 'contradicts' relationship
    const contradictionEdges = graph.edges.filter((e) => e.type === "contradicts");
    expect(contradictionEdges.length).toBeGreaterThanOrEqual(1);
  });

  it("builds an unverified/inconclusive graph for Scenario C", () => {
    const graph = buildTrustGraph(DEMO_SCENARIO_C);

    const entityNode = graph.nodes.find((n) => n.id === "node-entity");
    expect(entityNode?.status).toBe("unverified");

    const verdictNode = graph.nodes.find((n) => n.id === "node-verdict");
    expect(verdictNode?.label).toBe("Unknown");
    expect(verdictNode?.status).toBe("unverified");

    const unverifiedClaims = graph.nodes.filter((n) => n.type === "claim" && n.status === "unverified");
    expect(unverifiedClaims.length).toBeGreaterThanOrEqual(2);
  });

  it("handles sparse/empty report without throwing or corrupting edges", () => {
    const minimalReport: InvestigationReport = {
      investigationId: "min-01",
      timestamp: "2026-10-27T12:00:00Z",
      originalUrl: "https://simple.test",
      normalizedUrl: "https://simple.test",
      observedDestination: {
        submittedUrl: "https://simple.test",
        normalizedUrl: "https://simple.test",
        submittedHost: "simple.test",
        destinationChanged: false,
        redirectChain: [],
      },
      checksPerformed: [],
      evidenceItems: [],
      observedFacts: {
        credentialOrPaymentRequest: false,
        downloadOrPermissionRequest: false,
        formsObserved: false,
        hasPasswordField: false,
        hasPaymentField: false,
        hasPunycode: false,
        isNumericIp: false,
        isHttp: false,
      },
      modelInterpretations: [],
      warningSigns: [],
      missingEvidence: [],
      actionPreview: {
        proposedAction: "Inspect",
        consequenceIfProceed: "None",
        riskFactors: [],
      },
      riskOutcome: "Low observed risk",
      threatLikelihood: "Low",
      consequenceImpact: "Low",
      outcomeReason: "Sparse report",
      recommendedAction: "None",
      limitations: [],
      eventsCount: 0,
    };

    const graph = buildTrustGraph(minimalReport);
    expect(graph.nodes.length).toBeGreaterThanOrEqual(3);
    expect(graph.edges.length).toBeGreaterThanOrEqual(2);
    expect(graph.nodes.find((n) => n.id === "node-verdict")).toBeDefined();
  });
});
