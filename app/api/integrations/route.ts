import { NextResponse } from "next/server";
import { IntegrationRegistry } from "@/lib/integrations/registry";
import { PlatformType } from "@/lib/integrations/types";
import {
  isAllowedOrigin,
  checkRateLimit,
  getClientIp,
  createCorsHeaders,
  createCorsForbiddenResponse,
} from "@/lib/api-security";

export const runtime = "nodejs";

function getCorsHeaders(request: Request): Record<string, string> {
  return createCorsHeaders(request, "GET, POST, OPTIONS");
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) {
    return createCorsForbiddenResponse(request, "OPTIONS preflight request missing Origin header.");
  }
  if (!isAllowedOrigin(origin, request)) {
    return createCorsForbiddenResponse(request, `Origin '${origin}' is not authorized by AheadGuard security policy.`);
  }
  return new Response(null, {
    status: 204,
    headers: {
      ...getCorsHeaders(request),
      "Access-Control-Max-Age": "86400",
    },
  });
}

export async function GET(request: Request) {
  const origin = request.headers.get("origin");
  if (origin && !isAllowedOrigin(origin, request)) {
    return createCorsForbiddenResponse(request, `Origin '${origin}' is not authorized.`);
  }

  const clientIp = getClientIp(request);
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Too many requests. Please wait." },
      { status: 429, headers: getCorsHeaders(request) }
    );
  }

  const { searchParams } = new URL(request.url);
  const userId = searchParams.get("userId") || "default_user";

  const registry = IntegrationRegistry.getInstance();
  const summary = await registry.getSummary(userId);

  return NextResponse.json(
    {
      ok: true,
      integrations: summary,
      timestamp: new Date().toISOString(),
    },
    { headers: getCorsHeaders(request) }
  );
}

export async function POST(request: Request) {
  const origin = request.headers.get("origin");
  if (origin && !isAllowedOrigin(origin, request)) {
    return createCorsForbiddenResponse(request, `Origin '${origin}' is not authorized.`);
  }

  const clientIp = getClientIp(request);
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Too many requests. Please wait." },
      { status: 429, headers: getCorsHeaders(request) }
    );
  }

  try {
    const body = (await request.json()) as {
      action: "connect" | "disconnect" | "test";
      platform: PlatformType;
      userId?: string;
      credentials?: Record<string, string>;
      authCode?: string;
    };

    const { action, platform, userId = "default_user", credentials, authCode } = body;
    const registry = IntegrationRegistry.getInstance();
    const adapter = registry.getAdapter(platform);

    if (!adapter) {
      return NextResponse.json(
        { error: `Platform '${platform}' is not supported.` },
        { status: 400, headers: getCorsHeaders(request) }
      );
    }

    if (action === "connect") {
      const result = await adapter.connect({
        userId,
        credentials,
        authCode,
      });
      return NextResponse.json(result, { headers: getCorsHeaders(request) });
    }

    if (action === "disconnect") {
      await adapter.disconnect(userId);
      return NextResponse.json(
        { success: true, status: "DISCONNECTED", platform },
        { headers: getCorsHeaders(request) }
      );
    }

    if (action === "test") {
      const testResult = adapter.testConnection
        ? await adapter.testConnection(userId)
        : { ok: true, message: "Adapter is registered.", latencyMs: 1 };
      return NextResponse.json(testResult, { headers: getCorsHeaders(request) });
    }

    return NextResponse.json(
      { error: "Invalid action. Expected 'connect', 'disconnect', or 'test'." },
      { status: 400, headers: getCorsHeaders(request) }
    );
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to process integration request." },
      { status: 500, headers: getCorsHeaders(request) }
    );
  }
}
