import { NextResponse } from "next/server";
import { z } from "zod";
import { evaluateOfferIntegrity, FLAGSHIP_SCENARIO_INPUT } from "@/lib/offer-integrity/offer-evaluator";
import { ENTERPRISE_RECRUITMENT_POLICIES } from "@/lib/offer-integrity/policy-verifier";
import {
  isAllowedOrigin,
  checkRateLimit,
  getClientIp,
  createCorsHeaders,
  createCorsForbiddenResponse,
} from "@/lib/api-security";
import { extractEntitiesFromContent } from "@/lib/trustgraph/entity-extractor";
import { TrustGraphStore } from "@/lib/trustgraph/graph-store";
import { saveInvestigation, testDatabaseConnection } from "@/lib/db";
import type { InvestigationReport } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 60;

const OfferInputSchema = z.object({
  offerMessage: z.string().trim().min(5, "Offer message must be at least 5 characters.").max(10000),
  claimedCompany: z.string().trim().max(200).optional(),
  claimedRole: z.string().trim().max(200).optional(),
  recruiterName: z.string().trim().max(200).optional(),
  recruiterDesignation: z.string().trim().max(200).optional(),
  senderEmail: z.string().trim().max(320).optional(),
  senderPhone: z.string().trim().max(50).optional(),
  vacancyUrl: z.string().trim().max(2048).optional(),
  applicationUrl: z.string().trim().max(2048).optional(),
  paymentAmount: z.string().trim().max(50).optional(),
  paymentReason: z.string().trim().max(500).optional(),
  allowLiveCrawl: z.boolean().optional(),
  simulateCheckFailure: z.boolean().optional(),
  simulatePolicyFailure: z.boolean().optional(),
  simulateTinyFishFailure: z.boolean().optional(),
  tinyFishApiKey: z.string().trim().max(500).optional(),
});

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
    return NextResponse.json({ error: "Too many requests. Please wait." }, { status: 429 });
  }

  const dbStatus = await testDatabaseConnection();

  return NextResponse.json(
    {
      ok: true,
      module: "Offer Integrity Intelligence 2.1",
      tagline: "Check an internship offer before you pay.",
      coreDistinction: "A genuine internship can be used to make a fraudulent payment request look believable.",
      flagshipScenario: FLAGSHIP_SCENARIO_INPUT,
      policyDirectorySize: Object.keys(ENTERPRISE_RECRUITMENT_POLICIES).length,
      dbStatus,
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
      { error: "Too many verification requests. Please wait before submitting another offer." },
      { status: 429, headers: getCorsHeaders(request) }
    );
  }

  try {
    let rawJson: unknown;
    try {
      rawJson = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON request body." }, { status: 400, headers: getCorsHeaders(request) });
    }

    const parseResult = OfferInputSchema.safeParse(rawJson);
    if (!parseResult.success) {
      const issue = parseResult.error.issues[0];
      return NextResponse.json(
        { error: issue?.message || "Invalid offer input parameters." },
        { status: 400, headers: getCorsHeaders(request) }
      );
    }

    const input = parseResult.data;
    const report = await evaluateOfferIntegrity(input);

    // Ingest extracted entities into TrustGraph
    try {
      const graphStore = TrustGraphStore.getInstance();
      const combinedText = [
        input.offerMessage,
        input.claimedCompany,
        input.claimedRole,
        input.recruiterName,
        input.senderEmail,
      ].filter(Boolean).join("\n");

      const entities = extractEntitiesFromContent({
        text: combinedText,
        claimedOrg: input.claimedCompany,
        recruiter: input.recruiterName,
      });

      graphStore.ingestInvestigationEntities({
        investigationId: report.investigationId,
        platform: "universal_share",
        entities,
        riskOutcome: report.riskOutcome,
      });
    } catch {
      // Graph ingest non-fatal
    }

    // Persist to Neon Postgres if available
    let persisted = false;
    try {
      const dbCheck = await testDatabaseConnection();
      if (dbCheck.ok) {
        // Construct standard report envelope for database persistence
        const persistedReport: InvestigationReport = {
          investigationId: report.investigationId,
          timestamp: report.timestamp,
          originalUrl: input.vacancyUrl || input.applicationUrl || "https://aheadguard-ai.vercel.app/offer-check",
          normalizedUrl: input.vacancyUrl || input.applicationUrl || "https://aheadguard-ai.vercel.app/offer-check",
          observedDestination: {
            submittedUrl: input.vacancyUrl || "offer-text",
            normalizedUrl: input.vacancyUrl || "offer-text",
            submittedHost: report.offerBreakdown.vacancy.officialDomain || "offer-check",
            destinationChanged: false,
            redirectChain: [],
          },
          checksPerformed: [
            { name: "Offer Claim Extraction", status: "completed", detail: `Extracted ${report.claimsLedger.length} material claims.` },
            { name: "Vacancy Requisition Match", status: "completed", detail: report.offerBreakdown.vacancy.explanation },
            { name: "Recruitment Policy Verification", status: "completed", detail: report.offerBreakdown.policy.explanation },
            { name: "Payment Contradiction Check", status: "completed", detail: report.offerBreakdown.payment.explanation },
          ],
          evidenceItems: report.claimsLedger.map((c) => ({
            label: c.claimTitle,
            detail: c.explanation,
            kind: c.status === "CONTRADICTED" ? "warning" : c.status === "SUPPORTED" ? "positive" : "neutral",
            provenance: "policy_rule",
            id: c.id,
            evidenceNature: "direct_observation",
            sourceType: "observed_destination",
            sourceUrl: c.sourceUrl || "offer-message",
            observedAt: c.observationTime,
            accessible: true,
          })),
          observedFacts: {
            pageTitle: `Offer Check: ${report.offerBreakdown.vacancy.roleTitle}`,
            visiblePurpose: report.overallAssessment.verdictSummary,
            credentialOrPaymentRequest: report.offerBreakdown.payment.paymentRequested,
            downloadOrPermissionRequest: false,
            formsObserved: false,
            hasPasswordField: false,
            hasPaymentField: report.offerBreakdown.payment.paymentRequested,
            hasPunycode: false,
            isNumericIp: false,
            isHttp: false,
          },
          modelInterpretations: [
            {
              aspect: "Offer Integrity Analysis",
              interpretation: report.coreDistinctionNotice,
              confidence: "high",
            },
          ],
          warningSigns: report.offerBreakdown.payment.conflictsWithPolicy
            ? [report.offerBreakdown.payment.explanation]
            : [],
          missingEvidence: report.investigationLimitations,
          actionPreview: {
            proposedAction: "Evaluating internship offer before paying interview fee.",
            consequenceIfProceed: report.safeActionPlan.primaryWarning,
            riskFactors: [],
          },
          riskOutcome: report.riskOutcome,
          threatLikelihood: report.threatLikelihood,
          consequenceImpact: report.consequenceImpact,
          outcomeReason: report.overallAssessment.verdictSummary,
          recommendedAction: report.overallAssessment.recommendedAction,
          limitations: report.investigationLimitations,
          eventsCount: report.claimsLedger.length,
          offerIntegrity: report,
          persisted: true,
          storageMode: "persisted",
        };

        const dbRes = await saveInvestigation(persistedReport);
        if (dbRes.ok) {
          persisted = true;
        }
      }
    } catch {
      persisted = false;
    }

    return NextResponse.json(
      {
        ok: true,
        report,
        persisted,
      },
      { headers: getCorsHeaders(request) }
    );
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : "Offer investigation failed.";
    return NextResponse.json({ error: errorMsg }, { status: 500, headers: getCorsHeaders(request) });
  }
}
