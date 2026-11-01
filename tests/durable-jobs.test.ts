import { describe, it, expect, beforeEach } from "vitest";
import { JobStore } from "../lib/jobs/job-store";
import { DurableWorker } from "../lib/jobs/durable-worker";
import { InvestigationJobPayload } from "../lib/jobs/types";

describe("AheadGuard AI 3.0 — Headless Durable Execution Engine", () => {
  const store = JobStore.getInstance();
  const worker = DurableWorker.getInstance();

  beforeEach(() => {
    store.resetForTesting();
  });

  describe("JobStore State Machine & Idempotency", () => {
    it("enqueues a new investigation job with QUEUED status", async () => {
      const payload: InvestigationJobPayload = {
        inputCategory: "url",
        rawInput: "https://suspicious-login.top/account",
        targetUrl: "https://suspicious-login.top/account",
      };

      const { job, isDuplicate } = await store.enqueueJob({
        idempotencyKey: "tg_msg_101",
        platform: "telegram",
        senderId: "user_42",
        sourceAccountId: "chat_99",
        payload,
      });

      expect(job.id).toBeDefined();
      expect(job.status).toBe("QUEUED");
      expect(job.idempotencyKey).toBe("tg_msg_101");
      expect(job.attempts).toBe(0);
      expect(isDuplicate).toBe(false);
    });

    it("enforces strict idempotency deduplication on repeated deliveries", async () => {
      const payload: InvestigationJobPayload = {
        inputCategory: "url",
        rawInput: "https://duplicate-check.com",
      };

      const first = await store.enqueueJob({
        idempotencyKey: "discord_interaction_555",
        platform: "discord",
        senderId: "discord_user_1",
        sourceAccountId: "channel_1",
        payload,
      });

      const second = await store.enqueueJob({
        idempotencyKey: "discord_interaction_555",
        platform: "discord",
        senderId: "discord_user_1",
        sourceAccountId: "channel_1",
        payload,
      });

      expect(first.isDuplicate).toBe(false);
      expect(second.isDuplicate).toBe(true);
      expect(second.job.id).toBe(first.job.id);
    });

    it("acquires lease on queued job and advances status to PROCESSING", async () => {
      await store.enqueueJob({
        idempotencyKey: "key_lease_test",
        platform: "telegram",
        senderId: "user_1",
        sourceAccountId: "chat_1",
        payload: { inputCategory: "message", rawInput: "hello" },
      });

      const leasedJob = await store.acquireJobLease(10000);
      expect(leasedJob).not.toBeNull();
      expect(leasedJob?.status).toBe("PROCESSING");
      expect(leasedJob?.leaseToken).toBeDefined();
      expect(leasedJob?.attempts).toBe(1);

      // Subsequent immediate lease attempt returns null since no other job is queued
      const emptyLease = await store.acquireJobLease(10000);
      expect(emptyLease).toBeNull();
    });

    it("marks job COMPLETED when finished with investigation result", async () => {
      const { job } = await store.enqueueJob({
        idempotencyKey: "key_complete_test",
        platform: "whatsapp",
        senderId: "phone_123",
        sourceAccountId: "phone_123",
        payload: { inputCategory: "message", rawInput: "payment request" },
      });

      const leased = await store.acquireJobLease(10000);
      expect(leased).not.toBeNull();

      const success = await store.completeJob(job.id, leased!.leaseToken!, {
        type: "system",
        message: "Completed investigation successfully.",
      });

      expect(success).toBe(true);

      const updated = await store.getJob(job.id);
      expect(updated?.status).toBe("COMPLETED");
      expect(updated?.result).toBeDefined();
      expect(updated?.leaseToken).toBeNull();
    });

    it("transitions to DEAD_LETTER when maximum retry attempts are exhausted", async () => {
      const { job } = await store.enqueueJob({
        idempotencyKey: "key_failure_test",
        platform: "telegram",
        senderId: "user_fail",
        sourceAccountId: "chat_fail",
        maxAttempts: 2,
        payload: { inputCategory: "url", rawInput: "https://fail.test" },
      });

      // Attempt 1
      const lease1 = await store.acquireJobLease();
      expect(lease1?.attempts).toBe(1);
      const isDead1 = await store.failJob(job.id, lease1!.leaseToken!, "Connection timeout");
      expect(isDead1).toBe(false);

      const jobAfter1 = await store.getJob(job.id);
      expect(jobAfter1?.status).toBe("RETRY_WAIT");

      // Attempt 2 (reaches maxAttempts = 2)
      const lease2 = await store.acquireJobLease();
      expect(lease2?.attempts).toBe(2);
      const isDead2 = await store.failJob(job.id, lease2!.leaseToken!, "Second timeout");
      expect(isDead2).toBe(true);

      const jobAfter2 = await store.getJob(job.id);
      expect(jobAfter2?.status).toBe("DEAD_LETTER");
      expect(jobAfter2?.errorMessage).toBe("Second timeout");
    });

    it("recovers an expired lease when worker crashes or times out", async () => {
      const { job } = await store.enqueueJob({
        idempotencyKey: "key_expired_lease_recovery",
        platform: "telegram",
        senderId: "user_crash",
        sourceAccountId: "chat_crash",
        payload: { inputCategory: "message", rawInput: "recover me" },
      });

      // Lease for 1ms
      const lease1 = await store.acquireJobLease(1);
      expect(lease1?.id).toBe(job.id);
      expect(lease1?.status).toBe("PROCESSING");

      // Wait 10ms for lease to expire
      await new Promise((r) => setTimeout(r, 10));

      // Worker 2 attempts lease acquisition and recovers the abandoned job
      const lease2 = await store.acquireJobLease(10000);
      expect(lease2).not.toBeNull();
      expect(lease2?.id).toBe(job.id);
      expect(lease2?.attempts).toBe(2);
      expect(lease2?.leaseToken).not.toBe(lease1?.leaseToken);
    });

    it("prevents concurrent workers from acquiring the same active lease", async () => {
      await store.enqueueJob({
        idempotencyKey: "key_concurrency_race",
        platform: "telegram",
        senderId: "user_race",
        sourceAccountId: "chat_race",
        payload: { inputCategory: "message", rawInput: "race condition test" },
      });

      const [worker1Acquired, worker2Acquired] = await Promise.all([
        store.acquireJobLease(10000),
        store.acquireJobLease(10000),
      ]);

      const acquiredJobs = [worker1Acquired, worker2Acquired].filter(Boolean);
      expect(acquiredJobs.length).toBe(1);
    });
  });

  describe("DurableWorker End-to-End Execution", () => {
    it("processes system commands (/start, /help, /privacy) cleanly", async () => {
      const { job } = await store.enqueueJob({
        idempotencyKey: "cmd_privacy_test",
        platform: "telegram",
        senderId: "user_privacy",
        sourceAccountId: "chat_privacy",
        payload: {
          inputCategory: "message",
          rawInput: "/privacy",
          command: "/privacy",
        },
      });

      const result = await worker.executeJob(job);
      expect(result.success).toBe(true);
      expect(result.status).toBe("COMPLETED");
      expect(result.result?.type).toBe("system");
      if (result.result?.type === "system") {
        expect(result.result.message).toContain("Zero Passive Monitoring");
        expect(result.result.message).toContain("AheadGuard Privacy");
      }
    });

    it("executes Offer Integrity checks durably for job offer payloads", async () => {
      const offerText =
        "Congratulations! You have been selected for a remote Software Engineer Internship at Google. To confirm your placement and receive your company laptop and training kit, please deposit a refundable security fee of ₹4,999 to UPI ID hr-google-verify@okaxis within 24 hours. Contact Priya Sharma at priya.recruiter@gmail.com to proceed.";

      const { job } = await store.enqueueJob({
        idempotencyKey: "offer_job_flagship",
        platform: "telegram",
        senderId: "student_user",
        sourceAccountId: "chat_student",
        payload: {
          inputCategory: "job_offer",
          rawInput: offerText,
          command: "/offer",
          targetUrl: "https://careers.google.com/jobs/results/123",
        },
      });

      const result = await worker.executeJob(job);
      expect(result.success).toBe(true);
      expect(result.status).toBe("COMPLETED");
      expect(result.result?.type).toBe("offer");

      if (result.result?.type === "offer") {
        expect(result.result.riskOutcome).toBe("High risk");
        expect(result.result.report.offerBreakdown.vacancy.vacancyStatus).toBe("SUPPORTED");
        expect(result.result.report.offerBreakdown.payment.paymentStatus).toBe("CONTRADICTED");
        expect(result.result.report.offerBreakdown.sender.affiliationStatus).toBe("UNVERIFIED");
        expect(result.result.report.coreDistinctionNotice).toContain("THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE");
      }
    });

    it("executes standard orchestrator investigations durably for URL payloads", async () => {
      const { job } = await store.enqueueJob({
        idempotencyKey: "url_job_test",
        platform: "telegram",
        senderId: "user_url",
        sourceAccountId: "chat_url",
        payload: {
          inputCategory: "url",
          rawInput: "https://paypal-security-alert-login.online/verify",
          targetUrl: "https://paypal-security-alert-login.online/verify",
        },
      });

      const result = await worker.executeJob(job);
      expect(result.success).toBe(true);
      expect(result.status).toBe("COMPLETED");
      expect(result.result?.type).toBe("standard");
      if (result.result?.type === "standard") {
        expect(["High risk", "Suspicious"]).toContain(result.result.riskOutcome);
      }
    });
  });
});
