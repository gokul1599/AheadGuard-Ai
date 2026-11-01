import { NormalizedInvestigationRequest, StandardizedInvestigationResult } from "./types";
import { extractEntitiesFromContent } from "../trustgraph/entity-extractor";
import { TrustGraphStore } from "../trustgraph/graph-store";
import { analyzePaymentScreenshot, TransactionVerificationReport } from "../transaction-truth/screenshot-forensics";
import { inspectQrPayload, QrInspectionReport } from "../transaction-truth/qr-inspector";
import { analyzeMessageText } from "../message-intelligence";
import { verifyCompanyIdentity, verifyJobListing } from "../company-verification";
import { enrichReportWithScamIntelligence, createTextOnlyReport } from "../claims-evaluator";
import { validateAndNormalizeUrl } from "../url-safety";
import { assessInvestigation } from "../policy";
import { executeTinyFishInvestigation } from "../tinyfish";
import { InvestigationReport } from "../types";

export class InvestigationOrchestrator {
  private static instance?: InvestigationOrchestrator;
  private graphStore = TrustGraphStore.getInstance();

  public static getInstance(): InvestigationOrchestrator {
    if (!InvestigationOrchestrator.instance) {
      InvestigationOrchestrator.instance = new InvestigationOrchestrator();
    }
    return InvestigationOrchestrator.instance;
  }

  /**
   * Universal orchestration entry point.
   * Dispatches to specialized intelligence services and aggregates findings.
   */
  public async orchestrateInvestigation(
    request: NormalizedInvestigationRequest,
    options?: { onProgress?: (msg: string) => void; enableLiveBrowser?: boolean }
  ): Promise<StandardizedInvestigationResult> {
    const notify = options?.onProgress || (() => {});
    notify("Initiating AheadGuard Central Intelligence Orchestrator...");

    // 1. Entity Extraction
    notify("Extracting cross-platform entities (phone, domain, UPI, handles)...");
    const combinedText = [request.rawInput, request.messageText, request.ocrText].filter(Boolean).join("\n");
    const extractedEntities = extractEntitiesFromContent({
      text: combinedText,
      url: request.targetUrl,
      claimedOrg: request.claimedOrganization,
      recruiter: request.recruiterContact,
    });

    // 2. Transaction Truth Forensics (if screenshot OCR or QR payload present)
    let transactionTruth: TransactionVerificationReport | undefined;
    if (
      request.ocrText ||
      request.inputCategory === "payment_screenshot" ||
      combinedText.includes("UTR") ||
      combinedText.includes("UPI Ref")
    ) {
      notify("Executing Transaction Truth payment forensics...");
      transactionTruth = analyzePaymentScreenshot({
        ocrText: request.ocrText || combinedText,
        claimedBeneficiary: request.claimedOrganization,
      });
    }

    // 3. QR Code Inspection
    let qrInspection: QrInspectionReport | undefined;
    if (request.qrPayload || request.inputCategory === "qr_code") {
      notify("Inspecting QR code payload...");
      qrInspection = inspectQrPayload(request.qrPayload || request.rawInput);
    }

    // 4. Resolve Target URL
    let targetUrl = request.targetUrl;
    if (!targetUrl) {
      const domainEntity = extractedEntities.find((e) => e.type === "DOMAIN");
      if (domainEntity) {
        targetUrl = domainEntity.value.startsWith("http") ? domainEntity.value : `https://${domainEntity.value}`;
      }
    }

    let report: InvestigationReport;

    // 5. Analysis: Message Intelligence, Company & Job Verification
    const messageData = analyzeMessageText({
      rawMessage: combinedText || targetUrl || "Investigation query",
      userSpecifiedOrg: request.claimedOrganization,
      userSpecifiedRole: request.claimedJobRole,
      targetUrl,
    });

    const companyIdentity = verifyCompanyIdentity({
      claimedOrg: request.claimedOrganization || messageData.claimedOrganization,
      destinationUrl: targetUrl,
    });

    const jobVerification = request.claimedJobRole
      ? verifyJobListing({
          claimedEmployer: request.claimedOrganization || messageData.claimedOrganization,
          claimedRole: request.claimedJobRole,
          recruiterContact: request.recruiterContact,
          jobListingUrl: targetUrl,
          companyIdentity,
          feeWarningPresent: Boolean(messageData.recruitmentFeeWarning?.detected),
        })
      : undefined;

    // 6. Destination Investigation vs. Text-Only Investigation
    if (targetUrl) {
      notify(`Validating target URL safety: ${targetUrl}`);
      const validation = validateAndNormalizeUrl(targetUrl);

      if (!validation.valid) {
        // Destination failed SSRF / safety preflight
        report = assessInvestigation({
          submittedUrl: new URL("http://localhost"), // Fallback URL for assessment
          tinyFishResult: {
            success: false,
            goalFailed: true,
            errorMessage: validation.error,
            eventsCount: 0,
            rawAgentText: validation.error,
          },
        });
        report.originalUrl = targetUrl;
        report.normalizedUrl = targetUrl;
      } else if (options?.enableLiveBrowser && process.env.TINYFISH_API_KEY) {
        notify("Executing isolated remote browser sandbox via TinyFish...");
        const result = await executeTinyFishInvestigation({
          url: validation.normalizedUrl,
          apiKey: process.env.TINYFISH_API_KEY,
          onProgress: (evt) => notify(evt.message),
        });
        report = assessInvestigation({
          submittedUrl: validation.url,
          tinyFishResult: result,
        });
      } else {
        // Safe heuristic / offline investigation
        notify("Evaluating target destination heuristics...");
        report = assessInvestigation({
          submittedUrl: validation.url,
          tinyFishResult: {
            success: true,
            goalFailed: false,
            eventsCount: 0,
            rawAgentText: "",
          },
        });
      }

      // Enrich report with scam and company intelligence
      report = enrichReportWithScamIntelligence({
        report,
        messageData,
        companyIdentity,
        jobVerification,
        analysisMode: request.inputCategory === "job_offer" ? "job" : "link",
      });
    } else {
      // Text-only investigation
      notify("Evaluating text message intelligence & claim consistency...");
      report = createTextOnlyReport({
        messageData,
        companyIdentity,
        jobVerification,
      });
    }

    // 7. Apply Transaction Truth & QR Warnings to Overall Outcome
    if (transactionTruth?.isSpoofSuspected) {
      if (report.riskOutcome !== "High risk") {
        report.riskOutcome = "Suspicious";
        report.threatLikelihood = "High";
        report.warningSigns.push(...transactionTruth.warningSigns);
        report.outcomeReason = "Suspicious transaction evidence: Payment receipt shows indications of a spoof generator APK.";
      }
    }

    if (qrInspection?.isCollectRequest) {
      report.riskOutcome = "High risk";
      report.threatLikelihood = "High";
      report.consequenceImpact = "Severe";
      report.warningSigns.push(
        "Deceptive QR code: Encodes a debit payment transfer masquerading as a refund."
      );
      report.outcomeReason = "High risk: Scanning and entering PIN on this QR will transfer money out of your account.";
    }

    // 8. Ingest into TrustGraph & Detect Cross-Channel Campaigns
    notify("Connecting observables into TrustGraph...");
    const { nodes, edges, campaignSignal } = this.graphStore.ingestInvestigationEntities({
      investigationId: request.investigationId,
      platform: request.sourcePlatform,
      entities: extractedEntities,
      riskOutcome: report.riskOutcome,
    });

    if (campaignSignal.isCrossChannelCampaign) {
      report.warningSigns.push(campaignSignal.summary);
      if (report.riskOutcome === "Low observed risk") {
        report.riskOutcome = "Suspicious";
        report.outcomeReason = campaignSignal.summary;
      }
    }

    // 9. Synthesize Safe Action Plan
    const safeActionPlan = this.generateSafeActionPlan(report, transactionTruth, qrInspection);

    notify("Investigation complete. Structured report assembled.");

    return {
      investigationId: request.investigationId,
      timestamp: new Date().toISOString(),
      sourcePlatform: request.sourcePlatform,
      inputCategory: request.inputCategory,
      riskOutcome: report.riskOutcome,
      threatLikelihood: report.threatLikelihood,
      consequenceImpact: report.consequenceImpact,
      outcomeReason: report.outcomeReason,
      recommendedAction: report.recommendedAction,
      report,
      trustGraph: {
        nodes,
        edges,
        campaignSignal,
      },
      transactionTruth,
      qrInspection,
      safeActionPlan,
    };
  }

  private generateSafeActionPlan(
    report: InvestigationReport,
    transactionTruth?: TransactionVerificationReport,
    qrInspection?: QrInspectionReport
  ) {
    const stepByStep: string[] = [];
    const whatNotToDo: string[] = [];
    const safeAlternative = "Navigate to the company's official corporate homepage via a verified search or bookmark.";

    if (qrInspection?.isCollectRequest) {
      stepByStep.push("Never enter your UPI PIN to receive money or refunds.");
      stepByStep.push("Block and report the sender on your payment application.");
      whatNotToDo.push("Do not enter your PIN into any prompt claiming to receive a refund.");
      whatNotToDo.push("Do not scan unknown QR codes sent via WhatsApp or Telegram.");
    }

    if (transactionTruth?.isSpoofSuspected) {
      stepByStep.push("Check your bank statement or merchant soundbox directly.");
      stepByStep.push("Do not rely on screenshots presented on a customer's phone.");
      whatNotToDo.push("Do not dispatch goods or release services based on visual screenshots alone.");
    }

    if (report.scamIntelligence?.recruitmentFeeWarning?.detected) {
      stepByStep.push("Legitimate employers never demand upfront security deposits, registration fees, or training fees.");
      stepByStep.push("Verify the job posting on the official company careers portal.");
      whatNotToDo.push("Never transfer money via UPI or wire transfer for an interview, registration fee, or laptop dispatch.");
    }

    if (report.riskOutcome === "High risk") {
      stepByStep.push("Close the destination tab immediately.");
      stepByStep.push("Do not enter passwords, credit cards, or two-factor authentication codes.");
      whatNotToDo.push("Do not download attachments or install APK files from this source.");
    }

    if (stepByStep.length === 0) {
      stepByStep.push("Verify the sender's identity through an independent channel.");
      stepByStep.push("Confirm that the domain matches official published records.");
    }

    if (whatNotToDo.length === 0) {
      whatNotToDo.push("Do not share OTPs, passwords, or personal identity documents.");
    }

    return {
      primaryWarning: report.outcomeReason,
      stepByStepGuidance: stepByStep,
      safeAlternative,
      whatNotToDo,
    };
  }
}
