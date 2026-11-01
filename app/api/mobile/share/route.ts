import { NextResponse } from "next/server";
import { z } from "zod";
import { isAllowedOrigin, checkRateLimit, getClientIp } from "@/lib/api-security";
import { JobStore } from "@/lib/jobs/job-store";
import { DurableWorker } from "@/lib/jobs/durable-worker";

export const runtime = "nodejs";

const MobileShareSchema = z.object({
  platform: z.enum(["android", "ios"]),
  sharedText: z.string().trim().max(10000).optional(),
  sharedUrl: z.string().trim().url().max(2048).optional(),
  appVersion: z.string().trim().max(50).optional(),
  deviceModel: z.string().trim().max(100).optional(),
  clientNonce: z.string().trim().max(64).optional(),
}).refine((data) => Boolean(data.sharedText || data.sharedUrl), {
  message: "Either sharedText or sharedUrl must be provided.",
});

export async function POST(request: Request) {
  const origin = request.headers.get("origin");
  const headers: Record<string, string> = {
    "Vary": "Origin",
  };
  if (origin && isAllowedOrigin(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
  }

  const clientIp = getClientIp(request);
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait before submitting another share intent." },
      { status: 429, headers }
    );
  }

  try {
    const json = await request.json();
    const parsed = MobileShareSchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid share payload", details: parsed.error.issues },
        { status: 400, headers }
      );
    }

    const data = parsed.data;
    const rawText = data.sharedText || data.sharedUrl || "";
    const isOffer =
      rawText.toLowerCase().includes("interview") ||
      rawText.toLowerCase().includes("internship") ||
      rawText.toLowerCase().includes("job offer");

    const idempotencyKey = `mob_${data.clientNonce || Date.now()}`;
    const jobStore = JobStore.getInstance();

    const { job } = await jobStore.enqueueJob({
      idempotencyKey,
      platform: "universal_share",
      senderId: data.deviceModel || "mobile_device",
      sourceAccountId: data.platform,
      payload: {
        inputCategory: isOffer ? "job_offer" : data.sharedUrl ? "url" : "message",
        rawInput: rawText,
        targetUrl: data.sharedUrl,
        messageText: data.sharedText,
        metadata: {
          platform: data.platform,
          deviceModel: data.deviceModel,
          appVersion: data.appVersion,
        },
      },
    });

    const worker = DurableWorker.getInstance();
    const execution = await worker.executeJob(job);

    return NextResponse.json(
      {
        ok: true,
        jobId: job.id,
        status: execution.status,
        result: execution.result,
      },
      { status: 200, headers }
    );
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal share error" },
      { status: 500, headers }
    );
  }
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin");
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
  };
  if (origin && isAllowedOrigin(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return new Response(null, { status: 204, headers });
}
