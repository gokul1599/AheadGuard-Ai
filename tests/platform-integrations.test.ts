import { describe, it, expect } from "vitest";
import { IntegrationRegistry } from "../lib/integrations/registry";
import { TelegramAdapter } from "../lib/integrations/telegram-adapter";
import { InstagramAdapter } from "../lib/integrations/instagram-adapter";
import { WhatsAppAdapter } from "../lib/integrations/whatsapp-adapter";
import { DiscordAdapter } from "../lib/integrations/discord-adapter";
import { EmailAdapter } from "../lib/integrations/email-adapter";
import { LinkedInAdapter } from "../lib/integrations/linkedin-adapter";

describe("Cross-Platform Integration Registry & Adapters", () => {
  const registry = IntegrationRegistry.getInstance();

  it("registers all 8 core platform adapters", async () => {
    const adapters = registry.getAllAdapters();
    expect(adapters.length).toBeGreaterThanOrEqual(8);

    const platforms = adapters.map((a) => a.platform);
    expect(platforms).toContain("telegram");
    expect(platforms).toContain("instagram");
    expect(platforms).toContain("whatsapp");
    expect(platforms).toContain("discord");
    expect(platforms).toContain("x");
    expect(platforms).toContain("gmail");
    expect(platforms).toContain("linkedin");
    expect(platforms).toContain("tiktok");
  });

  it("retrieves honest capabilities and policy notices for all platforms", async () => {
    const capabilities = await registry.getAllCapabilities();
    expect(capabilities.length).toBeGreaterThanOrEqual(8);

    const whatsappCap = capabilities.find((c) => c.platform === "whatsapp");
    expect(whatsappCap?.honestLimitationNotice).toContain("end-to-end encrypted");
    expect(whatsappCap?.unsupportedCapabilities.length).toBeGreaterThan(0);

    const igCap = capabilities.find((c) => c.platform === "instagram");
    expect(igCap?.honestLimitationNotice).toContain("Meta policies strictly prohibit");
  });

  describe("Telegram Bot Adapter", () => {
    const adapter = new TelegramAdapter({
      botToken: "test_bot_token",
      webhookSecret: "my_secret_token_123",
    });

    it("verifies webhook with valid secret token header", async () => {
      const validReq = new Request("http://localhost/api/investigate/webhook/telegram", {
        headers: { "x-telegram-bot-api-secret-token": "my_secret_token_123" },
      });
      const validRes = await adapter.verifyWebhook(validReq);
      expect(validRes.isValid).toBe(true);

      const invalidReq = new Request("http://localhost/api/investigate/webhook/telegram", {
        headers: { "x-telegram-bot-api-secret-token": "wrong_secret" },
      });
      const invalidRes = await adapter.verifyWebhook(invalidReq);
      expect(invalidRes.isValid).toBe(false);
    });

    it("normalizes slash commands and extracts URLs", async () => {
      const rawUpdate = {
        update_id: 1001,
        message: {
          message_id: 55,
          from: { id: 12345, username: "testuser", first_name: "Alice" },
          chat: { id: 9988, type: "private" },
          text: "/check https://portal-account-verify.online/login Urgent alert!",
          date: 1730000000,
        },
      };

      const event = await adapter.normalizeEvent(rawUpdate);
      expect(event.platform).toBe("telegram");
      expect(event.senderHandle).toBe("@testuser");
      expect(event.extractedUrls).toContain("https://portal-account-verify.online/login");
      expect(event.extractedEntities.commands).toContain("/check");
    });

    it("formats markdown Telegram bot reply message", () => {
      const reply = adapter.formatTelegramReply({
        riskOutcome: "High risk",
        target: "https://phishing.site",
        reasons: ["Active credential harvesting portal", "Lookalike domain"],
        safeAction: "Close tab and navigate via verified bookmark.",
      });

      expect(reply).toContain("🔴 *HIGH RISK*");
      expect(reply).toContain("https://phishing.site");
      expect(reply).toContain("Active credential harvesting");
    });
  });

  describe("Instagram Professional Adapter", () => {
    const adapter = new InstagramAdapter({
      appSecret: "test_fb_secret",
      verifyToken: "meta_verify_token_xyz",
    });

    it("handles Meta webhook subscription challenge (hub.challenge)", async () => {
      const req = new Request(
        "http://localhost/api/investigate/webhook/instagram?hub.mode=subscribe&hub.verify_token=meta_verify_token_xyz&hub.challenge=11559988"
      );
      const res = await adapter.verifyWebhook(req);
      expect(res.isValid).toBe(true);
      expect(res.challengeResponse).toBe("11559988");
    });

    it("normalizes incoming Instagram direct messages", async () => {
      const rawPayload = {
        object: "instagram",
        entry: [
          {
            id: "ig_business_123",
            messaging: [
              {
                sender: { id: "user_client_456" },
                recipient: { id: "ig_business_123" },
                timestamp: 1730000100,
                message: {
                  mid: "m_mid_8899",
                  text: "You won our sponsor giveaway! Claim $500 gift at https://gift-claim-reward.top/win",
                },
              },
            ],
          },
        ],
      };

      const event = await adapter.normalizeEvent(rawPayload);
      expect(event.platform).toBe("instagram");
      expect(event.senderIdentifier).toBe("user_client_456");
      expect(event.extractedUrls).toContain("https://gift-claim-reward.top/win");
    });
  });

  describe("WhatsApp Business Adapter", () => {
    const adapter = new WhatsAppAdapter({
      appSecret: "wa_secret_123",
      verifyToken: "wa_verify_token",
    });

    it("handles WhatsApp subscription challenge", async () => {
      const req = new Request(
        "http://localhost/api/investigate/webhook/whatsapp?hub.mode=subscribe&hub.verify_token=wa_verify_token&hub.challenge=778899"
      );
      const res = await adapter.verifyWebhook(req);
      expect(res.isValid).toBe(true);
      expect(res.challengeResponse).toBe("778899");
    });

    it("normalizes incoming payment requests and extract UPI IDs", async () => {
      const rawPayload = {
        object: "whatsapp_business_account",
        entry: [
          {
            id: "waba_id_999",
            changes: [
              {
                value: {
                  messaging_product: "whatsapp",
                  metadata: { display_phone_number: "+1555123456", phone_number_id: "phone_id_1" },
                  messages: [
                    {
                      from: "919876543210",
                      id: "wamid.HBgL...",
                      timestamp: "1730000200",
                      type: "text",
                      text: {
                        body: "Please transfer the ₹50 registration fee via UPI to recruitment.team@okaxis to confirm your interview.",
                      },
                    },
                  ],
                },
              },
            ],
          },
        ],
      };

      const event = await adapter.normalizeEvent(rawPayload);
      expect(event.platform).toBe("whatsapp");
      expect(event.senderIdentifier).toBe("919876543210");
      expect(event.extractedEntities.upiIds).toContain("recruitment.team@okaxis");
      expect(event.inputCategory).toBe("payment_screenshot");
    });
  });

  describe("Email, LinkedIn, & Discord Adapters", () => {
    it("normalizes Discord application interactions", async () => {
      const discordAdapter = new DiscordAdapter();
      const event = await discordAdapter.normalizeEvent({
        id: "interaction_999",
        type: 2,
        guild_id: "guild_888",
        data: {
          name: "check",
          options: [{ name: "target", value: "https://free-crypto-giveaway.top/drop" }],
        },
        user: { id: "user_777", username: "suspicious_bot" },
      });

      expect(event.platform).toBe("discord");
      expect(event.extractedUrls).toContain("https://free-crypto-giveaway.top/drop");
      expect(event.senderHandle).toBe("@suspicious_bot");
    });

    it("normalizes user-submitted email headers and attachments", async () => {
      const emailAdapter = new EmailAdapter();
      const event = await emailAdapter.normalizeEvent({
        from: "hr@careers-google.top",
        subject: "Interview Offer & Mandatory Laptop Security Deposit",
        body: "Attached is your offer letter. Pay $150 deposit to secure hardware.",
        headers: { "received-spf": "fail" },
      });

      expect(event.platform).toBe("gmail");
      expect(event.senderHandle).toBe("hr@careers-google.top");
      expect(event.metadata.spfStatus).toBe("fail");
    });

    it("normalizes LinkedIn recruiter submissions", async () => {
      const liAdapter = new LinkedInAdapter();
      const event = await liAdapter.normalizeEvent({
        recruiterName: "David Miller",
        companyName: "Netflix",
        jobRole: "Junior Reviewer",
        text: "Apply here: https://netflix-careers-portal.online/apply",
      });

      expect(event.platform).toBe("linkedin");
      expect(event.extractedEntities.companies).toContain("Netflix");
      expect(event.extractedUrls).toContain("https://netflix-careers-portal.online/apply");
    });
  });
});
