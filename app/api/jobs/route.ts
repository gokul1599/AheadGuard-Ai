import { NextResponse } from "next/server";
import { JobStore } from "@/lib/jobs/job-store";
import { checkRateLimit, getClientIp, createCorsHeaders } from "@/lib/api-security";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const headers = createCorsHeaders(request, "GET, OPTIONS");

  const clientIp = getClientIp(request);
  const rateLimit = checkRateLimit(clientIp);
  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait before querying job status again." },
      { status: 429, headers }
    );
  }

  const url = new URL(request.url);
  const jobId = url.searchParams.get("jobId");
  const idempotencyKey = url.searchParams.get("idempotencyKey");

  if (!jobId && !idempotencyKey) {
    return NextResponse.json(
      { error: "Query parameter 'jobId' or 'idempotencyKey' is required." },
      { status: 400, headers }
    );
  }

  const store = JobStore.getInstance();
  const job = jobId
    ? await store.getJob(jobId)
    : await store.getJobByIdempotencyKey(idempotencyKey!);

  if (!job) {
    return NextResponse.json(
      { error: "Investigation job not found." },
      { status: 404, headers }
    );
  }

  return NextResponse.json({ ok: true, job }, { status: 200, headers });
}

export async function OPTIONS(request: Request) {
  const headers = createCorsHeaders(request, "GET, OPTIONS");
  return new Response(null, { status: 204, headers });
}
