import { describe, it, expect, beforeEach } from "vitest";
import { POST } from "../app/api/investigate/webhook/[platform]/route";
import { TelegramAdapter } from "../lib/integrations/telegram-adapter";
import { JobStore } from "../lib/jobs/job-store";

describe("AheadGuard AI 3.0 — Telegram First-Class Embedded Integration E2E", () => {
  const store = JobStore.getInstance();

  beforeEach(() => {
    store.resetForTesting();
  });

  const createTelegramRequest = (update: Record<string, unknown>, secretToken = "aheadguard-tg-secret-v1") => {
    return new Request("http://localhost:3000/api/investigate/webhook/telegram", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": secretToken,
      },
      body: JSON.stringify(update),
    });
  };

  it("handles Telegram /start command and returns welcome guide", async () => {
    const update = {
      update_id: 20001,
      message: {
        message_id: 1,
        from: { id: 7771, username: "telegram_user", first_name: "John" },
        chat: { id: 7771, type: "private" },
        text: "/start",
        date: 1730000000,
      },
    };

    const req = createTelegramRequest(update);
    const res = await POST(req, { params: Promise.resolve({ platform: "telegram" }) });
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.method).toBe("sendMessage");
    expect(data.chat_id).toBe("7771");
    expect(data.text).toContain("Welcome to AheadGuard AI");
    expect(data.text).toContain("/offer");
    expect(data.text).toContain("/check");
    expect(data.parse_mode).toBe("Markdown");
  });

  it("handles Telegram /help command and returns capabilities", async () => {
    const update = {
      update_id: 20002,
      message: {
        message_id: 2,
        from: { id: 7771, username: "telegram_user" },
        chat: { id: 7771, type: "private" },
        text: "/help",
        date: 1730000010,
      },
    };

    const req = createTelegramRequest(update);
    const res = await POST(req, { params: Promise.resolve({ platform: "telegram" }) });
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.method).toBe("sendMessage");
    expect(data.text).toContain("Command Help");
    expect(data.text).toContain("/offer <text>");
  });

  it("handles Telegram /privacy command and affirms zero passive monitoring", async () => {
    const update = {
      update_id: 20003,
      message: {
        message_id: 3,
        from: { id: 7771, username: "telegram_user" },
        chat: { id: 7771, type: "private" },
        text: "/privacy",
        date: 1730000020,
      },
    };

    const req = createTelegramRequest(update);
    const res = await POST(req, { params: Promise.resolve({ platform: "telegram" }) });
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.method).toBe("sendMessage");
    expect(data.text).toContain("Zero Passive Monitoring");
    expect(data.text).toContain("Explicit Submission Only");
  });

  it("executes Flagship Offer Integrity scenario via Telegram and returns evidence-backed report", async () => {
    const offerMessage =
      "/offer Congratulations! You have been selected for a remote Software Engineer Internship at Google. To confirm your placement and receive your company laptop and training kit, please deposit a refundable security fee of ₹4,999 to UPI ID hr-google-verify@okaxis within 24 hours. Contact Priya Sharma at priya.recruiter@gmail.com to proceed.";

    const update = {
      update_id: 20004,
      message: {
        message_id: 4,
        from: { id: 9988, username: "jobseeker", first_name: "Rahul" },
        chat: { id: 9988, type: "private" },
        text: offerMessage,
        date: 1730000030,
      },
    };

    const req = createTelegramRequest(update);
    const res = await POST(req, { params: Promise.resolve({ platform: "telegram" }) });
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.method).toBe("sendMessage");
    expect(data.chat_id).toBe("9988");
    expect(data.text).toContain("HIGH RISK OFFER TRAP");
    expect(data.text).toContain("The internship can be real while the payment request is false");
    expect(data.text).toContain("Claimed Employer:* Google");
    expect(data.text).toContain("CONTRADICTED (Illegal upfront fee)");
    expect(data.text).toContain("UNVERIFIED (Consumer email domain)");
    expect(data.text).toContain("Safe Action Plan");
    expect(data.text).toContain("Google");
  });

  it("executes /check command on phishing links and delivers threat breakdown", async () => {
    const update = {
      update_id: 20005,
      message: {
        message_id: 5,
        from: { id: 3344, username: "victim" },
        chat: { id: 3344, type: "private" },
        text: "/check https://netflix-billing-update-urgent.cc/account",
        date: 1730000040,
      },
    };

    const req = createTelegramRequest(update);
    const res = await POST(req, { params: Promise.resolve({ platform: "telegram" }) });
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.method).toBe("sendMessage");
    expect(data.chat_id).toBe("3344");
    expect(data.text).toMatch(/HIGH RISK|SUSPICIOUS/);
    expect(data.text).toContain("Observable Findings");
  });

  it("rejects unauthorized webhook requests with invalid secret token", async () => {
    const update = {
      update_id: 20006,
      message: {
        message_id: 6,
        chat: { id: 1111 },
        text: "/check https://example.com",
      },
    };

    const adapter = new TelegramAdapter({ webhookSecret: "strict_secret_123" });
    const invalidReq = new Request("http://localhost:3000/api/investigate/webhook/telegram", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": "bad_token",
      },
      body: JSON.stringify(update),
    });

    const verification = await adapter.verifyWebhook(invalidReq);
    expect(verification.isValid).toBe(false);
  });
});
