import { NextResponse } from "next/server";
import { TrustGraphStore } from "@/lib/trustgraph/graph-store";
import {
  isAllowedOrigin,
  checkRateLimit,
  getClientIp,
  createCorsHeaders,
  createCorsForbiddenResponse,
} from "@/lib/api-security";

export const runtime = "nodejs";

function getCorsHeaders(request: Request): Record<string, string> {
  return createCorsHeaders(request, "GET, OPTIONS");
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

  const graphStore = TrustGraphStore.getInstance();
  const data = graphStore.getGraphData();

  return NextResponse.json(
    {
      ok: true,
      nodes: data.nodes,
      edges: data.edges,
      stats: {
        totalNodes: data.nodes.length,
        totalEdges: data.edges.length,
        maliciousEntities: data.nodes.filter((n) => n.confirmedMalicious).length,
      },
      timestamp: new Date().toISOString(),
    },
    { headers: getCorsHeaders(request) }
  );
}
