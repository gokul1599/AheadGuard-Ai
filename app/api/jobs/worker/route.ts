import { NextResponse } from "next/server";
import { DurableWorker } from "@/lib/jobs/durable-worker";

export const runtime = "nodejs";

export async function POST(request: Request) {
  // If ADMIN_SECRET_KEY is configured, enforce authorization
  const adminSecret = process.env.ADMIN_SECRET_KEY;
  if (adminSecret && adminSecret.trim().length > 0) {
    const authHeader = request.headers.get("authorization") || "";
    const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (bearerToken !== adminSecret) {
      return NextResponse.json({ error: "Unauthorized: Invalid admin credentials." }, { status: 401 });
    }
  }

  try {
    let limit = 5;
    try {
      const body = await request.json();
      if (typeof body?.limit === "number") {
        limit = Math.min(Math.max(body.limit, 1), 20);
      }
    } catch {
      // Body is optional
    }

    const worker = DurableWorker.getInstance();
    const results = await worker.processBatch(limit);

    return NextResponse.json({
      ok: true,
      processedCount: results.length,
      results,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Worker processing failed." },
      { status: 500 }
    );
  }
}
