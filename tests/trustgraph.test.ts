import { describe, it, expect, beforeEach } from "vitest";
import { extractEntitiesFromContent } from "../lib/trustgraph/entity-extractor";
import { TrustGraphStore } from "../lib/trustgraph/graph-store";

describe("TrustGraph — Cross-Platform Entity & Fraud Campaign Intelligence", () => {
  let store: TrustGraphStore;

  beforeEach(() => {
    store = TrustGraphStore.getInstance();
    store.clear();
  });

  describe("Entity Extractor", () => {
    it("extracts and normalizes phone numbers, domains, UPI VPAs, and emails", () => {
      const sampleText = `
        Contact our HR on +91 98765 43210 or email recruiter@careers-google.top.
        Register via https://portal-account-verify.online/login.
        Send $50 fee to recruitment.team@okaxis or via Telegram @hr_official.
      `;

      const entities = extractEntitiesFromContent({
        text: sampleText,
        url: "https://portal-account-verify.online/login",
        claimedOrg: "Google",
      });

      const types = entities.map((e) => e.type);
      expect(types).toContain("PHONE");
      expect(types).toContain("EMAIL");
      expect(types).toContain("DOMAIN");
      expect(types).toContain("UPI_VPA");
      expect(types).toContain("SOCIAL_HANDLE");
      expect(types).toContain("ORG_ENTITY");

      const upi = entities.find((e) => e.type === "UPI_VPA");
      expect(upi?.canonicalValue).toBe("recruitment.team@okaxis");

      const domain = entities.find((e) => e.type === "DOMAIN");
      expect(domain?.canonicalValue).toBe("portal-account-verify.online");
    });
  });

  describe("Graph Ingestion & Edge Stitching", () => {
    it("stitches relationships between claimed organizations, domains, and payment VPAs", () => {
      const entities = extractEntitiesFromContent({
        text: "Pay fee to recruitment.team@okaxis",
        url: "https://netflix-careers-portal.online/apply",
        claimedOrg: "Netflix",
      });

      const { nodes, edges } = store.ingestInvestigationEntities({
        investigationId: "inv_test_01",
        platform: "instagram",
        entities,
        riskOutcome: "High risk",
      });

      expect(nodes.length).toBeGreaterThanOrEqual(3);
      expect(edges.length).toBeGreaterThanOrEqual(2);

      const paymentEdge = edges.find((e) => e.relationshipType === "SOLICITS_PAYMENT_TO");
      expect(paymentEdge).toBeDefined();
      expect(paymentEdge?.sourceReliability).toBe("AUTHORITATIVE");
    });

    it("detects cross-channel coordinated fraud campaigns when identifiers recur across platforms", () => {
      // First investigation on Telegram
      const entities1 = extractEntitiesFromContent({
        text: "Contact support via UPI refund.desk@okaxis",
        url: "https://phishing-scam-center.xyz",
      });

      store.ingestInvestigationEntities({
        investigationId: "inv_telegram_101",
        platform: "telegram",
        entities: entities1,
        riskOutcome: "High risk",
      });

      // Second investigation on WhatsApp with the same UPI identifier
      const entities2 = extractEntitiesFromContent({
        text: "Job fee required. Pay to refund.desk@okaxis immediately.",
        url: "https://job-scam-hub.top",
      });

      const { campaignSignal } = store.ingestInvestigationEntities({
        investigationId: "inv_whatsapp_202",
        platform: "whatsapp",
        entities: entities2,
        riskOutcome: "High risk",
      });

      expect(campaignSignal.isCrossChannelCampaign).toBe(true);
      expect(campaignSignal.sharedEntities.length).toBeGreaterThanOrEqual(1);

      const shared = campaignSignal.sharedEntities.find((s) => s.value === "refund.desk@okaxis");
      expect(shared).toBeDefined();
      expect(shared?.platforms).toContain("telegram");
      expect(shared?.platforms).toContain("whatsapp");
      expect(campaignSignal.summary).toContain("Coordinated activity detected");
    });
  });
});
