import { NextResponse } from "next/server";
import { IntegrationRegistry } from "@/lib/integrations/registry";
import { PlatformType } from "@/lib/integrations/types";
import { TelegramAdapter } from "@/lib/integrations/telegram-adapter";
import { JobStore } from "@/lib/jobs/job-store";
import { DurableWorker } from "@/lib/jobs/durable-worker";

export const runtime = "nodejs";

// GET handler for subscription / challenge verification (Meta, Instagram, WhatsApp)
export async function GET(
  request: Request,
  context: { params: Promise<{ platform: string }> }
) {
  const { platform } = await context.params;
  const registry = IntegrationRegistry.getInstance();
  const adapter = registry.getAdapter(platform as PlatformType);

  if (!adapter) {
    return new Response(`Platform '${platform}' not found.`, { status: 404 });
  }

  const verification = await adapter.verifyWebhook(request);
  if (verification.isValid && verification.challengeResponse !== undefined) {
    return new Response(String(verification.challengeResponse), {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
  }

  return new Response("Webhook verification failed.", { status: 403 });
}

// POST handler for inbound platform events (Durable execution pipeline)
export async function POST(
  request: Request,
  context: { params: Promise<{ platform: string }> }
) {
  const { platform } = await context.params;
  const registry = IntegrationRegistry.getInstance();
  const adapter = registry.getAdapter(platform as PlatformType);

  if (!adapter) {
    return NextResponse.json({ error: `Platform '${platform}' not found.` }, { status: 404 });
  }

  const rawBody = await request.text();
  const verification = await adapter.verifyWebhook(request, rawBody);

  if (!verification.isValid) {
    return NextResponse.json(
      { error: "Forbidden: Webhook signature verification failed.", reason: verification.reason },
      { status: 403 }
    );
  }

  try {
    const jsonPayload = rawBody ? JSON.parse(rawBody) : {};

    // 1. Discord Endpoint Registration Challenge (PING -> PONG)
    if (platform === "discord" && jsonPayload.type === 1) {
      return NextResponse.json({ type: 1 });
    }

    // 2. Normalize event through the platform adapter
    const normalizedEvent = await adapter.normalizeEvent(jsonPayload);

    // 3. Construct deterministic idempotency key to prevent double execution on webhook retries
    const idempotencyKey =
      platform === "telegram"
        ? `tg_upd_${jsonPayload.update_id || normalizedEvent.eventId}`
        : platform === "discord"
        ? `discord_int_${jsonPayload.id || normalizedEvent.eventId}`
        : `${platform}_evt_${normalizedEvent.eventId}`;

    // 4. Enqueue durable investigation job
    const jobStore = JobStore.getInstance();
    const command = normalizedEvent.extractedEntities.commands?.[0];

    const { job, isDuplicate } = await jobStore.enqueueJob({
      idempotencyKey,
      platform: adapter.platform,
      senderId: normalizedEvent.senderIdentifier || "webhook_user",
      sourceAccountId: normalizedEvent.sourceAccountId || "default_channel",
      payload: {
        inputCategory: normalizedEvent.inputCategory,
        rawInput: normalizedEvent.rawText || "",
        messageText: normalizedEvent.rawText,
        targetUrl: normalizedEvent.extractedUrls[0],
        command,
        senderHandle: normalizedEvent.senderHandle,
        senderDisplayName: normalizedEvent.senderDisplayName,
        metadata: normalizedEvent.metadata,
      },
    });

    // 5. Execute job through Durable Worker
    const worker = DurableWorker.getInstance();
    const execution = await worker.executeJob(job);

    // 6. Platform-specific synchronous webhook replies
    if (platform === "telegram" && adapter instanceof TelegramAdapter) {
      let replyText = "";
      if (execution.result?.type === "system") {
        replyText = execution.result.message;
      } else if (execution.result?.type === "offer") {
        replyText = adapter.formatTelegramOfferReply(execution.result.report);
      } else if (execution.result?.type === "standard") {
        replyText = adapter.formatTelegramReply({
          riskOutcome: execution.result.riskOutcome,
          target: normalizedEvent.extractedUrls[0] || normalizedEvent.rawText?.slice(0, 50) || "Message",
          reasons: execution.result.report.warningSigns.slice(0, 3),
          safeAction: execution.result.safeAction,
        });
      } else {
        replyText = "⚠️ Unable to complete investigation. Please try again later.";
      }

      return NextResponse.json({
        method: "sendMessage",
        chat_id: normalizedEvent.sourceAccountId,
        text: replyText,
        parse_mode: "Markdown",
      });
    }

    if (platform === "discord") {
      let content = "";
      if (execution.result?.type === "offer") {
        content =
          `**[AheadGuard AI Offer Integrity]**\n` +
          `Outcome: **${execution.result.riskOutcome}**\n` +
          `*Company:* ${execution.result.report.offerBreakdown.vacancy.companyName}\n` +
          `*Summary:* ${execution.result.outcomeReason}\n` +
          `*Safe Action:* ${execution.result.safeAction}`;
      } else if (execution.result?.type === "standard") {
        content =
          `**[AheadGuard AI Verification]**\n` +
          `Outcome: **${execution.result.riskOutcome}**\n` +
          `${execution.result.outcomeReason}\n` +
          `*Safe Action:* ${execution.result.safeAction}`;
      } else {
        content = execution.result?.type === "system" ? execution.result.message : "AheadGuard verified.";
      }

      return NextResponse.json({
        type: 4, // CHANNEL_MESSAGE_WITH_SOURCE
        data: { content },
      });
    }

    return NextResponse.json({
      ok: true,
      jobId: job.id,
      isDuplicate,
      status: execution.status,
      result: execution.result,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to process webhook event." },
      { status: 500 }
    );
  }
}
