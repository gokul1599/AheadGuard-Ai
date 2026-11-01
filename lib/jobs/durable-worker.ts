import { JobStore } from "./job-store";
import { InvestigationJob, InvestigationJobResult } from "./types";
import { InvestigationOrchestrator } from "@/lib/orchestrator/investigation-orchestrator";
import { evaluateOfferIntegrity } from "@/lib/offer-integrity/offer-evaluator";
import { IntegrationRegistry } from "@/lib/integrations/registry";
import { TelegramAdapter } from "@/lib/integrations/telegram-adapter";
import { saveInvestigation } from "@/lib/db";
import type { InvestigationReport, RiskOutcome } from "@/lib/types";

export interface WorkerExecutionResult {
  success: boolean;
  jobId: string;
  status: import("./types").JobStatus;
  result?: InvestigationJobResult;
  error?: string;
}

/**
 * Headless Durable Worker for AheadGuard AI 3.0.
 * Decouples platform intake from investigation execution, ensuring that
 * serverless timeouts or killed function invocations do not drop pending investigations.
 */
export class DurableWorker {
  private static instance: DurableWorker;
  private jobStore = JobStore.getInstance();
  private orchestrator = InvestigationOrchestrator.getInstance();
  private registry = IntegrationRegistry.getInstance();

  private constructor() {}

  public static getInstance(): DurableWorker {
    if (!DurableWorker.instance) {
      DurableWorker.instance = new DurableWorker();
    }
    return DurableWorker.instance;
  }

  /**
   * Executes a specific investigation job to completion and dispatches results.
   */
  public async executeJob(job: InvestigationJob): Promise<WorkerExecutionResult> {
    const leaseToken = job.leaseToken || "manual_exec_token";

    try {
      let jobResult: InvestigationJobResult;

      // 1. Handle system slash commands directly
      if (job.payload.command === "/start" || job.payload.command === "/help" || job.payload.command === "/privacy") {
        const systemMessage = this.generateSystemMessage(job.payload.command);
        jobResult = {
          type: "system",
          message: systemMessage,
        };
      }
      // 2. Handle Offer Integrity checks
      else if (job.payload.inputCategory === "job_offer" || job.payload.command === "/offer") {
        const offerReport = await evaluateOfferIntegrity({
          offerMessage: job.payload.rawInput,
          vacancyUrl: job.payload.targetUrl,
        });

        // Persist to audit ledger
        const reportAdapter: InvestigationReport = {
          investigationId: offerReport.investigationId,
          timestamp: offerReport.timestamp,
          originalUrl: offerReport.offerBreakdown.destination.submittedUrl || "https://aheadguard-ai.vercel.app/offer-check",
          normalizedUrl: offerReport.offerBreakdown.destination.submittedUrl || "https://aheadguard-ai.vercel.app/offer-check",
          observedDestination: {
            submittedUrl: offerReport.offerBreakdown.destination.submittedUrl || "offer-text",
            normalizedUrl: offerReport.offerBreakdown.destination.submittedUrl || "offer-text",
            submittedHost: offerReport.offerBreakdown.vacancy.officialDomain || "offer-check",
            destinationChanged: false,
            redirectChain: [],
          },
          checksPerformed: [
            { name: "Offer Claim Extraction", status: "completed", detail: `Extracted ${offerReport.claimsLedger.length} material claims.` },
            { name: "Vacancy Requisition Match", status: "completed", detail: offerReport.offerBreakdown.vacancy.explanation },
            { name: "Recruitment Policy Verification", status: "completed", detail: offerReport.offerBreakdown.policy.explanation },
            { name: "Payment Contradiction Check", status: "completed", detail: offerReport.offerBreakdown.payment.explanation },
          ],
          evidenceItems: offerReport.claimsLedger.map((c) => ({
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
            pageTitle: `Offer Check: ${offerReport.offerBreakdown.vacancy.roleTitle}`,
            visiblePurpose: offerReport.overallAssessment.verdictSummary,
            credentialOrPaymentRequest: offerReport.offerBreakdown.payment.paymentRequested,
            downloadOrPermissionRequest: false,
            formsObserved: false,
            hasPasswordField: false,
            hasPaymentField: offerReport.offerBreakdown.payment.paymentRequested,
            hasPunycode: false,
            isNumericIp: false,
            isHttp: false,
          },
          modelInterpretations: [
            {
              aspect: "Offer Integrity Analysis",
              interpretation: offerReport.coreDistinctionNotice,
              confidence: "high",
            },
          ],
          warningSigns: offerReport.offerBreakdown.payment.conflictsWithPolicy
            ? [offerReport.offerBreakdown.payment.explanation]
            : [],
          missingEvidence: offerReport.investigationLimitations,
          actionPreview: {
            proposedAction: "Evaluating internship offer before paying interview fee.",
            consequenceIfProceed: offerReport.safeActionPlan.primaryWarning,
            riskFactors: [offerReport.coreDistinctionNotice],
          },
          riskOutcome: offerReport.riskOutcome,
          threatLikelihood: offerReport.threatLikelihood,
          consequenceImpact: offerReport.consequenceImpact,
          outcomeReason: offerReport.overallAssessment.verdictSummary,
          recommendedAction: offerReport.overallAssessment.recommendedAction,
          limitations: offerReport.investigationLimitations,
          eventsCount: offerReport.claimsLedger.length,
          persisted: true,
          storageMode: "persisted",
        };

        await saveInvestigation(reportAdapter);

        jobResult = {
          type: "offer",
          report: offerReport,
          riskOutcome: offerReport.riskOutcome,
          safeAction: offerReport.safeActionPlan.keyRecommendation,
          outcomeReason: offerReport.overallAssessment.verdictSummary,
        };
      }
      // 3. Handle standard web & message threat investigations
      else {
        const targetUrl = job.payload.targetUrl || (job.payload.inputCategory === "url" ? job.payload.rawInput : undefined);
        const result = await this.orchestrator.orchestrateInvestigation({
          investigationId: job.id,
          userId: job.senderId,
          sourcePlatform: job.platform,
          inputCategory: job.payload.inputCategory,
          rawInput: job.payload.rawInput,
          messageText: job.payload.messageText || job.payload.rawInput,
          targetUrl,
          hasExplicitUserConsent: true,
          timestamp: job.createdAt,
        });

        // Persist to audit ledger
        await saveInvestigation(result.report);

        jobResult = {
          type: "standard",
          report: result.report,
          riskOutcome: result.riskOutcome as RiskOutcome,
          safeAction: result.safeActionPlan.safeAlternative,
          outcomeReason: result.outcomeReason,
        };
      }

      // 4. Mark job completed in durable store
      await this.jobStore.completeJob(job.id, leaseToken, jobResult);

      // 5. Deliver result back to the originating native platform
      await this.deliverResult(job, jobResult);

      return {
        success: true,
        jobId: job.id,
        status: "COMPLETED",
        result: jobResult,
      };
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      await this.jobStore.failJob(job.id, leaseToken, errorMessage);

      return {
        success: false,
        jobId: job.id,
        status: "FAILED",
        error: errorMessage,
      };
    }
  }

  /**
   * Dispatches the formatted outcome to the originating platform (Telegram, Discord, WhatsApp, etc.).
   */
  public async deliverResult(
    job: InvestigationJob,
    result: InvestigationJobResult
  ): Promise<{ delivered: boolean; error?: string }> {
    const adapter = this.registry.getAdapter(job.platform);
    if (!adapter) return { delivered: false, error: "Adapter not registered" };

    try {
      if (job.platform === "telegram" && adapter instanceof TelegramAdapter) {
        let textToSend = "";

        if (result.type === "system") {
          textToSend = result.message;
        } else if (result.type === "offer") {
          textToSend = adapter.formatTelegramOfferReply(result.report);
        } else {
          textToSend = adapter.formatTelegramReply({
            riskOutcome: result.riskOutcome,
            target: job.payload.targetUrl || job.payload.rawInput.slice(0, 50),
            reasons: result.report.warningSigns.slice(0, 3),
            safeAction: result.safeAction,
          });
        }

        // Deliver via Telegram Bot API when TELEGRAM_BOT_TOKEN is set
        if (process.env.TELEGRAM_BOT_TOKEN) {
          await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: job.sourceAccountId,
              text: textToSend,
              parse_mode: "Markdown",
            }),
          });
        }

        return { delivered: true };
      }

      return { delivered: true };
    } catch (err) {
      return { delivered: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Processes the next available job in the queue.
   */
  public async processNextJob(): Promise<WorkerExecutionResult | null> {
    const job = await this.jobStore.acquireJobLease();
    if (!job) return null;
    return this.executeJob(job);
  }

  /**
   * Processes a batch of queued jobs.
   */
  public async processBatch(limit: number = 5): Promise<WorkerExecutionResult[]> {
    const results: WorkerExecutionResult[] = [];
    for (let i = 0; i < limit; i++) {
      const res = await this.processNextJob();
      if (!res) break;
      results.push(res);
    }
    return results;
  }

  private generateSystemMessage(command?: string): string {
    if (command === "/privacy") {
      return (
        "🔒 *AheadGuard Privacy & Trust Guarantee*\n\n" +
        "• *Zero Passive Monitoring:* We cannot and do not read your private chats.\n" +
        "• *Explicit Submission Only:* Only messages or URLs you explicitly send or forward are analyzed.\n" +
        "• *No Password/OTP Storage:* AheadGuard never asks for or stores credentials, bank passwords, or OTPs.\n" +
        "• *Immutable Audit Records:* Reports are cryptographically hashed and tied to your interaction.\n\n" +
        "_Your AI checks first. You act with confidence._"
      );
    }

    if (command === "/help") {
      return (
        "🛡️ *AheadGuard AI — Command Help*\n\n" +
        "• `/offer <text>` — Verify job & internship offers. Detects when real company jobs are weaponized with fake upfront fees.\n" +
        "• `/check <link or message>` — Scan URLs, redirect chains, and suspicious messages for phishing.\n" +
        "• `/payment <upi or details>` — Verify payment requests, QR destinations, and collect traps.\n" +
        "• `/website <url>` — Deep website investigation and entity verification.\n" +
        "• `/privacy` — Review our strict privacy protections.\n\n" +
        "_Tip: You can simply forward any suspicious message directly into this chat!_"
      );
    }

    // Default /start
    return (
      "🛡️ *Welcome to AheadGuard AI*\n" +
      "_Your AI checks first. You act with confidence._\n\n" +
      "I am your embedded digital trust agent. Before you trust a suspicious link, pay a registration deposit, or share sensitive details, forward the message to me.\n\n" +
      "*Try these commands:*\n" +
      "• Forward any message directly to this chat\n" +
      "• `/offer <paste offer message>` — Check internship/job fees\n" +
      "• `/check <link>` — Scan a website\n" +
      "• `/payment <details>` — Verify payment claims\n" +
      "• `/help` — Full list of capabilities"
    );
  }
}
