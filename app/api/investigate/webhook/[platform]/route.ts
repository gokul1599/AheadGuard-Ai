import { NextResponse } from "next/server";
import { IntegrationRegistry } from "@/lib/integrations/registry";
import { PlatformType } from "@/lib/integrations/types";
import { InvestigationOrchestrator } from "@/lib/orchestrator/investigation-orchestrator";
import { TelegramAdapter } from "@/lib/integrations/telegram-adapter";

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

// POST handler for inbound platform events
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

    // Discord Endpoint Registration Challenge (PING -> PONG)
    if (platform === "discord" && jsonPayload.type === 1) {
      return NextResponse.json({ type: 1 });
    }

    // Normalize event through the platform adapter
    const normalizedEvent = await adapter.normalizeEvent(jsonPayload);

    // Dispatch to the Central Investigation Orchestrator
    const orchestrator = InvestigationOrchestrator.getInstance();
    const investigationId = `inv_${platform}_${Date.now()}`;

    const result = await orchestrator.orchestrateInvestigation({
      investigationId,
      userId: normalizedEvent.senderIdentifier || "webhook_user",
      sourcePlatform: adapter.platform,
      inputCategory: normalizedEvent.inputCategory,
      rawInput: normalizedEvent.rawText || "",
      messageText: normalizedEvent.rawText,
      targetUrl: normalizedEvent.extractedUrls[0],
      hasExplicitUserConsent: true,
      timestamp: normalizedEvent.receivedAt,
    });

    // Platform-specific response formatting
    if (platform === "telegram" && adapter instanceof TelegramAdapter) {
      const telegramText = adapter.formatTelegramReply({
        riskOutcome: result.riskOutcome,
        target: normalizedEvent.extractedUrls[0] || normalizedEvent.rawText?.slice(0, 50) || "Message",
        reasons: result.report.warningSigns.slice(0, 3),
        safeAction: result.safeActionPlan.safeAlternative,
      });

      return NextResponse.json({
        method: "sendMessage",
        chat_id: normalizedEvent.sourceAccountId,
        text: telegramText,
        parse_mode: "Markdown",
      });
    }

    if (platform === "discord") {
      // Discord Interaction Response
      return NextResponse.json({
        type: 4, // CHANNEL_MESSAGE_WITH_SOURCE
        data: {
          content: `**[AheadGuard AI Verification]**\nOutcome: **${result.riskOutcome}**\n${result.outcomeReason}\n*Safe Action:* ${result.safeActionPlan.safeAlternative}`,
        },
      });
    }

    return NextResponse.json({
      ok: true,
      investigationId,
      result,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to process webhook event." },
      { status: 500 }
    );
  }
}
