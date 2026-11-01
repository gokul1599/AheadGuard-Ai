import { NextResponse } from "next/server";
import { TrustGraphStore } from "@/lib/trustgraph/graph-store";
import { isAllowedOrigin, checkRateLimit, getClientIp } from "@/lib/api-security";

export const runtime = "nodejs";

function getCorsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  if (origin && isAllowedOrigin(origin)) {
    return {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept",
      "Vary": "Origin",
    };
  }
  return { Vary: "Origin" };
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin || !isAllowedOrigin(origin)) {
    return new Response("CORS origin not allowed.", { status: 403 });
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
  if (origin && !isAllowedOrigin(origin)) {
    return new Response("CORS origin not allowed.", { status: 403 });
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
