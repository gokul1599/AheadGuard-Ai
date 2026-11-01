import { getDb, isDatabaseConfigured, withTimeout } from "@/lib/db";
import { InvestigationJob, EnqueueJobParams, InvestigationJobResult } from "./types";
import crypto from "node:crypto";

/**
 * Durable Job Store for AheadGuard AI 3.0 Headless Agent Execution.
 * Manages background investigation queues, idempotency deduplication,
 * safe concurrent lease locks, retries, and dead-letter classification.
 */
export class JobStore {
  private static instance: JobStore;

  // In-memory fallback map for test isolation and unconfigured environments
  private inMemoryJobs = new Map<string, InvestigationJob>();
  private inMemoryIdempotency = new Map<string, string>(); // idempotencyKey -> jobId
  private tableInitialized = false;

  private constructor() {}

  public static getInstance(): JobStore {
    if (!JobStore.instance) {
      JobStore.instance = new JobStore();
    }
    return JobStore.instance;
  }

  /**
   * Resets in-memory state (primarily for automated test isolation).
   */
  public resetForTesting(): void {
    this.inMemoryJobs.clear();
    this.inMemoryIdempotency.clear();
  }

  /**
   * Idempotently ensures the investigation_jobs table exists in PostgreSQL.
   */
  public async ensureTable(): Promise<void> {
    if (this.tableInitialized || !isDatabaseConfigured()) return;

    try {
      const sql = getDb();
      await withTimeout(
        sql`
          CREATE TABLE IF NOT EXISTS investigation_jobs (
            id VARCHAR(64) PRIMARY KEY,
            idempotency_key VARCHAR(128) UNIQUE NOT NULL,
            platform VARCHAR(32) NOT NULL,
            sender_id VARCHAR(128) NOT NULL,
            source_account_id VARCHAR(128) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
            payload JSONB NOT NULL,
            result JSONB,
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            lease_token VARCHAR(64),
            lease_expires_at TIMESTAMPTZ,
            error_message TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
          );
        `,
        5000
      );

      await withTimeout(
        sql`
          CREATE INDEX IF NOT EXISTS idx_jobs_status_lease 
          ON investigation_jobs (status, lease_expires_at);
        `,
        5000
      );

      await withTimeout(
        sql`
          CREATE INDEX IF NOT EXISTS idx_jobs_idempotency_key 
          ON investigation_jobs (idempotency_key);
        `,
        5000
      );

      this.tableInitialized = true;
    } catch {
      // Fallback gracefully to in-memory mode if table creation cannot proceed
    }
  }

  /**
   * Enqueues a new investigation job with strict idempotency deduplication.
   * If a job with the same idempotency key already exists, returns the existing job.
   */
  public async enqueueJob(params: EnqueueJobParams): Promise<{ job: InvestigationJob; isDuplicate: boolean }> {
    const existing = await this.getJobByIdempotencyKey(params.idempotencyKey);
    if (existing) {
      return { job: existing, isDuplicate: true };
    }

    const now = new Date().toISOString();
    const jobId = `job_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
    const newJob: InvestigationJob = {
      id: jobId,
      idempotencyKey: params.idempotencyKey,
      platform: params.platform,
      senderId: params.senderId,
      sourceAccountId: params.sourceAccountId,
      status: "QUEUED",
      payload: params.payload,
      result: null,
      attempts: 0,
      maxAttempts: params.maxAttempts || 3,
      leaseToken: null,
      leaseExpiresAt: null,
      errorMessage: null,
      createdAt: now,
      updatedAt: now,
    };

    // Store in-memory always for speed and resilience
    this.inMemoryJobs.set(jobId, newJob);
    this.inMemoryIdempotency.set(params.idempotencyKey, jobId);

    if (isDatabaseConfigured()) {
      try {
        await this.ensureTable();
        const sql = getDb();
        await withTimeout(
          sql`
            INSERT INTO investigation_jobs (
              id, idempotency_key, platform, sender_id, source_account_id,
              status, payload, attempts, max_attempts, created_at, updated_at
            ) VALUES (
              ${jobId}, ${params.idempotencyKey}, ${params.platform}, ${params.senderId},
              ${params.sourceAccountId}, 'QUEUED', ${JSON.stringify(params.payload)},
              0, ${newJob.maxAttempts}, ${now}, ${now}
            )
            ON CONFLICT (idempotency_key) DO NOTHING;
          `,
          3000
        );
      } catch {
        // In-memory record preserved
      }
    }

    return { job: newJob, isDuplicate: false };
  }

  /**
   * Atomically acquires a lease on the next available queued or timed-out job.
   */
  public async acquireJobLease(leaseDurationMs: number = 30000): Promise<InvestigationJob | null> {
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const leaseExpiresAt = new Date(nowMs + leaseDurationMs).toISOString();
    const leaseToken = crypto.randomUUID();

    // 1. Try database lease if configured
    if (isDatabaseConfigured()) {
      try {
        await this.ensureTable();
        const sql = getDb();
        const rows = (await withTimeout(
          sql`
            UPDATE investigation_jobs
            SET 
              status = 'PROCESSING',
              lease_token = ${leaseToken},
              lease_expires_at = ${leaseExpiresAt},
              attempts = attempts + 1,
              updated_at = ${nowIso}
            WHERE id = (
              SELECT id FROM investigation_jobs
              WHERE status = 'QUEUED'
                 OR (status = 'PROCESSING' AND lease_expires_at < ${nowIso})
              ORDER BY created_at ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
            )
            RETURNING *;
          `,
          3000
        )) as Array<Record<string, unknown>>;

        if (rows && rows.length > 0) {
          const r = rows[0];
          const dbJob: InvestigationJob = {
            id: String(r.id),
            idempotencyKey: String(r.idempotency_key),
            platform: r.platform as import("@/lib/integrations/types").PlatformType,
            senderId: String(r.sender_id),
            sourceAccountId: String(r.source_account_id),
            status: "PROCESSING",
            payload: typeof r.payload === "string" ? JSON.parse(r.payload) : (r.payload as import("./types").InvestigationJobPayload),
            result: typeof r.result === "string" ? JSON.parse(r.result) : (r.result as import("./types").InvestigationJobResult),
            attempts: Number(r.attempts || 1),
            maxAttempts: Number(r.max_attempts || 3),
            leaseToken,
            leaseExpiresAt,
            errorMessage: r.error_message ? String(r.error_message) : null,
            createdAt: r.created_at ? new Date(String(r.created_at)).toISOString() : nowIso,
            updatedAt: nowIso,
          };
          this.inMemoryJobs.set(dbJob.id, dbJob);
          return dbJob;
        }
      } catch {
        // Fall back to in-memory check
      }
    }

    // 2. In-memory queue lease acquisition
    for (const job of this.inMemoryJobs.values()) {
      const isExpired = job.status === "PROCESSING" && job.leaseExpiresAt && new Date(job.leaseExpiresAt).getTime() < nowMs;
      if (job.status === "QUEUED" || isExpired) {
        job.status = "PROCESSING";
        job.leaseToken = leaseToken;
        job.leaseExpiresAt = leaseExpiresAt;
        job.attempts += 1;
        job.updatedAt = nowIso;
        return { ...job };
      }
    }

    return null;
  }

  /**
   * Marks a job as completed and stores the evidence-backed investigation result.
   */
  public async completeJob(
    jobId: string,
    leaseToken: string,
    result: InvestigationJobResult
  ): Promise<boolean> {
    const nowIso = new Date().toISOString();
    const memJob = this.inMemoryJobs.get(jobId);
    if (memJob) {
      memJob.status = "COMPLETED";
      memJob.result = result;
      memJob.leaseToken = null;
      memJob.leaseExpiresAt = null;
      memJob.updatedAt = nowIso;
    }

    if (isDatabaseConfigured()) {
      try {
        const sql = getDb();
        await withTimeout(
          sql`
            UPDATE investigation_jobs
            SET 
              status = 'COMPLETED',
              result = ${JSON.stringify(result)},
              lease_token = NULL,
              lease_expires_at = NULL,
              updated_at = ${nowIso}
            WHERE id = ${jobId} AND (lease_token = ${leaseToken} OR lease_token IS NULL);
          `,
          3000
        );
      } catch {
        // memJob updated
      }
    }

    return true;
  }

  /**
   * Records a job failure. If attempts exceed maxAttempts, marks DEAD_LETTER.
   */
  public async failJob(
    jobId: string,
    leaseToken: string,
    errorMessage: string
  ): Promise<boolean> {
    const nowIso = new Date().toISOString();
    const memJob = this.inMemoryJobs.get(jobId);
    let isDeadLetter = false;

    if (memJob) {
      isDeadLetter = memJob.attempts >= memJob.maxAttempts;
      memJob.status = isDeadLetter ? "DEAD_LETTER" : "QUEUED";
      memJob.errorMessage = errorMessage;
      memJob.leaseToken = null;
      memJob.leaseExpiresAt = null;
      memJob.updatedAt = nowIso;
    }

    if (isDatabaseConfigured()) {
      try {
        const sql = getDb();
        await withTimeout(
          sql`
            UPDATE investigation_jobs
            SET 
              status = CASE WHEN attempts >= max_attempts THEN 'DEAD_LETTER' ELSE 'QUEUED' END,
              error_message = ${errorMessage},
              lease_token = NULL,
              lease_expires_at = NULL,
              updated_at = ${nowIso}
            WHERE id = ${jobId} AND (lease_token = ${leaseToken} OR lease_token IS NULL);
          `,
          3000
        );
      } catch {
        // memJob updated
      }
    }

    return isDeadLetter;
  }

  /**
   * Retrieves a job by ID.
   */
  public async getJob(jobId: string): Promise<InvestigationJob | null> {
    const memJob = this.inMemoryJobs.get(jobId);
    if (memJob) return { ...memJob };

    if (isDatabaseConfigured()) {
      try {
        const sql = getDb();
        const rows = (await withTimeout(
          sql`SELECT * FROM investigation_jobs WHERE id = ${jobId} LIMIT 1;`,
          2000
        )) as Array<Record<string, unknown>>;

        if (rows && rows.length > 0) {
          const r = rows[0];
          return {
            id: String(r.id),
            idempotencyKey: String(r.idempotency_key),
            platform: r.platform as import("@/lib/integrations/types").PlatformType,
            senderId: String(r.sender_id),
            sourceAccountId: String(r.source_account_id),
            status: r.status as import("./types").JobStatus,
            payload: typeof r.payload === "string" ? JSON.parse(r.payload) : (r.payload as import("./types").InvestigationJobPayload),
            result: typeof r.result === "string" ? JSON.parse(r.result) : (r.result as import("./types").InvestigationJobResult),
            attempts: Number(r.attempts || 0),
            maxAttempts: Number(r.max_attempts || 3),
            leaseToken: r.lease_token ? String(r.lease_token) : null,
            leaseExpiresAt: r.lease_expires_at ? new Date(String(r.lease_expires_at)).toISOString() : null,
            errorMessage: r.error_message ? String(r.error_message) : null,
            createdAt: String(r.created_at),
            updatedAt: String(r.updated_at),
          };
        }
      } catch {
        return null;
      }
    }

    return null;
  }

  /**
   * Retrieves a job by its idempotency key.
   */
  public async getJobByIdempotencyKey(key: string): Promise<InvestigationJob | null> {
    const jobId = this.inMemoryIdempotency.get(key);
    if (jobId) {
      return this.getJob(jobId);
    }

    if (isDatabaseConfigured()) {
      try {
        const sql = getDb();
        const rows = (await withTimeout(
          sql`SELECT * FROM investigation_jobs WHERE idempotency_key = ${key} LIMIT 1;`,
          2000
        )) as Array<Record<string, unknown>>;

        if (rows && rows.length > 0) {
          const r = rows[0];
          const j: InvestigationJob = {
            id: String(r.id),
            idempotencyKey: String(r.idempotency_key),
            platform: r.platform as import("@/lib/integrations/types").PlatformType,
            senderId: String(r.sender_id),
            sourceAccountId: String(r.source_account_id),
            status: r.status as import("./types").JobStatus,
            payload: typeof r.payload === "string" ? JSON.parse(r.payload) : (r.payload as import("./types").InvestigationJobPayload),
            result: typeof r.result === "string" ? JSON.parse(r.result) : (r.result as import("./types").InvestigationJobResult),
            attempts: Number(r.attempts || 0),
            maxAttempts: Number(r.max_attempts || 3),
            leaseToken: r.lease_token ? String(r.lease_token) : null,
            leaseExpiresAt: r.lease_expires_at ? new Date(String(r.lease_expires_at)).toISOString() : null,
            errorMessage: r.error_message ? String(r.error_message) : null,
            createdAt: String(r.created_at),
            updatedAt: String(r.updated_at),
          };
          this.inMemoryJobs.set(j.id, j);
          this.inMemoryIdempotency.set(key, j.id);
          return j;
        }
      } catch {
        return null;
      }
    }

    return null;
  }
}
