import crypto from "node:crypto";
import { ExtractedEntity } from "./entity-extractor";

export interface TrustGraphNode {
  id: string; // SHA-256(canonicalValue:type)
  type: string;
  canonicalValue: string;
  displayValue: string;
  firstSeenAt: string;
  lastObservedAt: string;
  occurrenceCount: number;
  reputationScore: number; // 0.0 (clean) to 1.0 (confirmed malicious)
  confirmedMalicious: boolean;
  associatedInvestigationIds: string[];
  associatedPlatforms: string[];
}

export interface TrustGraphEdge {
  id: string;
  sourceId: string;
  targetId: string;
  relationshipType:
    | "SOLICITS_PAYMENT_TO"
    | "CLAIMS_REPRESENTATION"
    | "REDIRECTS_TO"
    | "USES_PHONE"
    | "USES_EMAIL"
    | "ASSOCIATED_WITH";
  provenanceSource: "TINYFISH_DOM" | "RDAP_REGISTRY" | "USER_SUBMISSION" | "PAYMENT_EXTRACTION" | "MESSAGE_TEXT";
  sourceReliability: "AUTHORITATIVE" | "OBSERVED_SANDBOX" | "INFERRED_MODEL" | "UNVERIFIED_COMMUNITY";
  confidenceScore: number;
  investigationId: string;
  observedAt: string;
}

export interface CrossChannelCampaignSignal {
  isCrossChannelCampaign: boolean;
  campaignId?: string;
  sharedEntities: Array<{ type: string; value: string; platforms: string[]; count: number }>;
  summary: string;
}

export class TrustGraphStore {
  private static instance?: TrustGraphStore;

  private nodes = new Map<string, TrustGraphNode>();
  private edges = new Map<string, TrustGraphEdge>();

  private constructor() {}

  public static getInstance(): TrustGraphStore {
    if (!TrustGraphStore.instance) {
      TrustGraphStore.instance = new TrustGraphStore();
    }
    return TrustGraphStore.instance;
  }

  public generateNodeId(canonicalValue: string, type: string): string {
    return crypto.createHash("sha256").update(`${type.toUpperCase()}:${canonicalValue.toLowerCase()}`).digest("hex").slice(0, 16);
  }

  public upsertNode(entity: ExtractedEntity, investigationId: string, platform: string): TrustGraphNode {
    const id = this.generateNodeId(entity.canonicalValue, entity.type);
    const existing = this.nodes.get(id);
    const now = new Date().toISOString();

    if (existing) {
      existing.lastObservedAt = now;
      existing.occurrenceCount += 1;
      if (!existing.associatedInvestigationIds.includes(investigationId)) {
        existing.associatedInvestigationIds.push(investigationId);
      }
      if (!existing.associatedPlatforms.includes(platform)) {
        existing.associatedPlatforms.push(platform);
      }
      return existing;
    }

    const newNode: TrustGraphNode = {
      id,
      type: entity.type,
      canonicalValue: entity.canonicalValue,
      displayValue: entity.value,
      firstSeenAt: now,
      lastObservedAt: now,
      occurrenceCount: 1,
      reputationScore: 0.1,
      confirmedMalicious: false,
      associatedInvestigationIds: [investigationId],
      associatedPlatforms: [platform],
    };

    this.nodes.set(id, newNode);
    return newNode;
  }

  public addEdge(edgeData: Omit<TrustGraphEdge, "id" | "observedAt">): TrustGraphEdge {
    const id = crypto
      .createHash("sha256")
      .update(`${edgeData.sourceId}->${edgeData.relationshipType}->${edgeData.targetId}`)
      .digest("hex")
      .slice(0, 16);

    const edge: TrustGraphEdge = {
      ...edgeData,
      id,
      observedAt: new Date().toISOString(),
    };

    this.edges.set(id, edge);
    return edge;
  }

  /**
   * Ingests a full batch of entities extracted from an investigation and stitches edges between them.
   */
  public ingestInvestigationEntities(params: {
    investigationId: string;
    platform: string;
    entities: ExtractedEntity[];
    riskOutcome: string;
  }): { nodes: TrustGraphNode[]; edges: TrustGraphEdge[]; campaignSignal: CrossChannelCampaignSignal } {
    const nodes: TrustGraphNode[] = [];
    const edges: TrustGraphEdge[] = [];

    // 1. Upsert all nodes
    for (const entity of params.entities) {
      const node = this.upsertNode(entity, params.investigationId, params.platform);
      if (params.riskOutcome === "High risk") {
        node.reputationScore = Math.min(1.0, node.reputationScore + 0.4);
        node.confirmedMalicious = true;
      } else if (params.riskOutcome === "Suspicious") {
        node.reputationScore = Math.min(1.0, node.reputationScore + 0.2);
      }
      nodes.push(node);
    }

    // 2. Stitch relationships
    const domainNode = nodes.find((n) => n.type === "DOMAIN");
    const orgNode = nodes.find((n) => n.type === "ORG_ENTITY");
    const upiNode = nodes.find((n) => n.type === "UPI_VPA");
    const phoneNode = nodes.find((n) => n.type === "PHONE");

    if (domainNode && orgNode) {
      edges.push(
        this.addEdge({
          sourceId: domainNode.id,
          targetId: orgNode.id,
          relationshipType: "CLAIMS_REPRESENTATION",
          provenanceSource: "MESSAGE_TEXT",
          sourceReliability: "OBSERVED_SANDBOX",
          confidenceScore: 0.9,
          investigationId: params.investigationId,
        })
      );
    }

    if (upiNode && (orgNode || domainNode)) {
      edges.push(
        this.addEdge({
          sourceId: (domainNode || orgNode)!.id,
          targetId: upiNode.id,
          relationshipType: "SOLICITS_PAYMENT_TO",
          provenanceSource: "PAYMENT_EXTRACTION",
          sourceReliability: "AUTHORITATIVE",
          confidenceScore: 0.98,
          investigationId: params.investigationId,
        })
      );
    }

    if (phoneNode && (domainNode || orgNode)) {
      edges.push(
        this.addEdge({
          sourceId: phoneNode.id,
          targetId: (domainNode || orgNode)!.id,
          relationshipType: "ASSOCIATED_WITH",
          provenanceSource: "USER_SUBMISSION",
          sourceReliability: "OBSERVED_SANDBOX",
          confidenceScore: 0.85,
          investigationId: params.investigationId,
        })
      );
    }

    // 3. Detect Cross-Channel Campaigns
    const sharedEntities = nodes
      .filter((n) => n.associatedPlatforms.length > 1 || n.occurrenceCount > 1)
      .map((n) => ({
        type: n.type,
        value: n.displayValue,
        platforms: n.associatedPlatforms,
        count: n.occurrenceCount,
      }));

    const isCrossChannel = sharedEntities.length > 0;
    const campaignSignal: CrossChannelCampaignSignal = {
      isCrossChannelCampaign: isCrossChannel,
      campaignId: isCrossChannel ? `cmp_${nodes[0]?.id || "multi"}` : undefined,
      sharedEntities,
      summary: isCrossChannel
        ? `Coordinated activity detected: ${sharedEntities.length} shared identifier(s) observed across [${Array.from(
            new Set(sharedEntities.flatMap((s) => s.platforms))
          ).join(", ")}].`
        : "No previous cross-platform correlation found for these entities.",
    };

    return { nodes, edges, campaignSignal };
  }

  public getGraphData(): { nodes: TrustGraphNode[]; edges: TrustGraphEdge[] } {
    return {
      nodes: Array.from(this.nodes.values()),
      edges: Array.from(this.edges.values()),
    };
  }

  public clear(): void {
    this.nodes.clear();
    this.edges.clear();
  }
}
