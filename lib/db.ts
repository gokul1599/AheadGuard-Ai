import { neon, NeonQueryFunction, Client, neonConfig } from "@neondatabase/serverless";
import { InvestigationReport } from "./types";
import { createShareableReport, sanitizeUrlForSharing } from "./share-report";

export type TaggedQueryFunction = (
  strings: TemplateStringsArray,
  ...values: unknown[]
) => Promise<unknown[]>;

export interface SessionQueryClient {
  query: (text: string, values?: unknown[]) => Promise<{ rows: unknown[] }>;
  connect?: () => Promise<void>;
  end?: () => Promise<void>;
}

let wsConfigured = false;
export function ensureWebSocketConfigured(): void {
  if (wsConfigured) return;
  if (!neonConfig.webSocketConstructor) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const ws = require("ws");
      neonConfig.webSocketConstructor = ws;
    } catch {
      if (typeof globalThis.WebSocket !== "undefined") {
        neonConfig.webSocketConstructor = globalThis.WebSocket;
      }
    }
  }
  wsConfigured = true;
}

export function createSessionSql(client: {
  query: (text: string, values?: unknown[]) => Promise<{ rows: unknown[] }>;
}): TaggedQueryFunction {
  return async (strings: TemplateStringsArray, ...values: unknown[]) => {
    let queryText = "";
    for (let i = 0; i < strings.length; i++) {
      queryText += strings[i];
      if (i < values.length) {
        queryText += String(values[i]);
      }
    }
    const res = await client.query(queryText);
    return res.rows;
  };
}

let cachedSql: NeonQueryFunction<false, false> | null = null;

/**
 * Bounds any asynchronous operation with an explicit timeout.
 */
export async function withTimeout<T>(promise: Promise<T>, ms: number = 5000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Database operation timed out after ${ms}ms`));
    }, ms);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Returns whether a Neon DATABASE_URL is configured in the environment.
 */
export function isDatabaseConfigured(): boolean {
  return Boolean(process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0);
}

/**
 * Gets the Neon serverless SQL client instance.
 * Automatically caches the client instance at module scope.
 */
export function getDb(): NeonQueryFunction<false, false> {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl || dbUrl.trim().length === 0) {
    throw new Error(
      "Neon DATABASE_URL is not configured. Add your Neon connection string to .env.local or production environment variables."
    );
  }

  if (!cachedSql) {
    cachedSql = neon(dbUrl);
  }
  return cachedSql;
}

export type DatabaseConnectionStatus = "connected" | "unconfigured" | "unavailable";

export interface DatabaseConnectionResult {
  ok: boolean;
  status: DatabaseConnectionStatus;
  error?: string;
}

/**
 * Validates the structure and contract consistency of an API health check response.
 *
 * Requirements:
 * - data must be an object with a 'db' property
 * - db.ok must be boolean
 * - db.status must be one of: 'connected', 'unconfigured', 'unavailable'
 * - Consistency: if status === 'connected', ok must be true
 * - Consistency: if status !== 'connected', ok must be false
 * - In strict persistence mode: status must be 'connected' and ok must be true
 */
export function validateDatabaseHealthContract(
  data: unknown,
  options?: { strictConnected?: boolean }
): { valid: boolean; error?: string; status?: DatabaseConnectionStatus; ok?: boolean } {
  if (!data || typeof data !== "object") {
    return { valid: false, error: "Response body is not a valid JSON object." };
  }

  const payload = data as Record<string, unknown>;
  if (!("db" in payload) || !payload.db || typeof payload.db !== "object") {
    return { valid: false, error: "Missing or invalid 'db' object in response." };
  }

  const db = payload.db as Record<string, unknown>;
  if (typeof db.ok !== "boolean") {
    return { valid: false, error: "Property 'db.ok' must be a boolean." };
  }

  const validStatuses: DatabaseConnectionStatus[] = ["connected", "unconfigured", "unavailable"];
  if (typeof db.status !== "string" || !validStatuses.includes(db.status as DatabaseConnectionStatus)) {
    return {
      valid: false,
      error: `Property 'db.status' must be one of: ${validStatuses.join(", ")}; received "${String(db.status)}"`,
    };
  }

  const status = db.status as DatabaseConnectionStatus;

  // Strict internal consistency check
  if (status === "connected" && !db.ok) {
    return { valid: false, error: "Inconsistent state: status is 'connected' but 'ok' is false." };
  }
  if (status !== "connected" && db.ok) {
    return { valid: false, error: `Inconsistent state: status is '${status}' but 'ok' is true.` };
  }

  // If error string is present, ensure it does not leak credentials or connection strings
  if (typeof db.error === "string") {
    const lower = db.error.toLowerCase();
    if (lower.includes("password") || lower.includes("neon.tech") || lower.includes("postgres://") || lower.includes("postgresql://")) {
      return { valid: false, error: "Security violation: db.error contains leaked credential or host details." };
    }
  }

  if (options?.strictConnected && (status !== "connected" || !db.ok)) {
    return {
      valid: false,
      status,
      ok: db.ok,
      error: `Strict database persistence check failed: expected status 'connected' with ok:true, but got status '${status}' (ok: ${db.ok}).`,
    };
  }

  return { valid: true, status, ok: db.ok };
}

/**
 * Tests connectivity to the configured Neon database with a minimal, safe query (SELECT 1).
 * Never leaks database credentials, host details, SQL version strings, or internal error traces.
 */
export async function testDatabaseConnection(): Promise<DatabaseConnectionResult> {
  if (!isDatabaseConfigured()) {
    return {
      ok: false,
      status: "unconfigured",
      error: "DATABASE_URL environment variable is not configured.",
    };
  }

  try {
    const sql = getDb();
    const result = await withTimeout(sql`SELECT 1 as alive;`, 3000);
    const firstRow = result[0] as { alive?: number } | undefined;

    if (firstRow && firstRow.alive === 1) {
      return {
        ok: true,
        status: "connected",
      };
    }

    return {
      ok: false,
      status: "unavailable",
      error: "Database connectivity check did not return expected response.",
    };
  } catch {
    return {
      ok: false,
      status: "unavailable",
      error: "Unable to reach database service.",
    };
  }
}

export interface SchemaValidationResult {
  ok: boolean;
  errors: string[];
}

export const REQUIRED_COLUMNS: Record<string, { dataType: string; isNullable: boolean }> = {
  id: { dataType: "character varying", isNullable: false },
  original_url: { dataType: "text", isNullable: false },
  final_url: { dataType: "text", isNullable: true },
  risk_outcome: { dataType: "character varying", isNullable: false },
  threat_likelihood: { dataType: "character varying", isNullable: false },
  consequence_impact: { dataType: "character varying", isNullable: false },
  claimed_organization: { dataType: "text", isNullable: true },
  analysis_mode: { dataType: "character varying", isNullable: true },
  report_json: { dataType: "jsonb", isNullable: false },
  created_at: { dataType: "timestamp with time zone", isNullable: true },
};

/**
 * Validates the core table structure for public.investigations (columns, data types, nullability, primary key).
 * Run prior to any DDL or index mutations to ensure an existing table is structurally compatible.
 */
export async function validateTableStructure(
  sql: TaggedQueryFunction | NeonQueryFunction<false, false>
): Promise<SchemaValidationResult> {
  const errors: string[] = [];

  // 1. Query column definitions
  const columns = (await withTimeout(
    sql`
      SELECT
        column_name,
        data_type,
        is_nullable
      FROM information_schema.columns
      WHERE table_name = 'investigations' AND table_schema = 'public';
    `,
    5000
  )) as Array<{ column_name?: string; data_type?: string; is_nullable?: string }>;

  const colMap = new Map<string, { dataType: string; isNullable: boolean }>();
  for (const col of columns || []) {
    if (col?.column_name) {
      colMap.set(col.column_name.toLowerCase(), {
        dataType: (col.data_type || "").toLowerCase(),
        isNullable: (col.is_nullable || "").toUpperCase() === "YES",
      });
    }
  }

  for (const [colName, expected] of Object.entries(REQUIRED_COLUMNS)) {
    const actual = colMap.get(colName);
    if (!actual) {
      errors.push(`Missing required column '${colName}'`);
    } else {
      if (actual.dataType !== expected.dataType) {
        errors.push(
          `Column '${colName}' data type mismatch: expected '${expected.dataType}', found '${actual.dataType}'`
        );
      }
      if (!expected.isNullable && actual.isNullable) {
        errors.push(`Column '${colName}' nullability mismatch: must be NOT NULL`);
      }
    }
  }

  // 2. Query primary key constraint
  const pks = (await withTimeout(
    sql`
      SELECT kcu.column_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name
        AND tc.table_schema = kcu.table_schema
      WHERE tc.constraint_type = 'PRIMARY KEY'
        AND tc.table_name = 'investigations'
        AND tc.table_schema = 'public';
    `,
    5000
  )) as Array<{ column_name?: string }>;

  const pkCol = pks?.[0]?.column_name?.toLowerCase();
  if (pkCol !== "id") {
    errors.push(
      `Primary key mismatch on 'investigations': expected single primary key on 'id', found '${pkCol || "none"}'`
    );
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Validates the complete PostgreSQL schema, constraints, and index definitions for public.investigations.
 * Detects missing columns, data-type mismatches, nullability violations, missing primary keys,
 * missing or invalid indexes, incorrect index sort orders, and foreign index name collisions.
 */
export async function validateDatabaseSchema(
  sql: TaggedQueryFunction | NeonQueryFunction<false, false>
): Promise<SchemaValidationResult> {
  const structureVal = await validateTableStructure(sql);
  const errors: string[] = [...structureVal.errors];

  // 3. Query index definitions on public.investigations
  const indexes = (await withTimeout(
    sql`
      SELECT
        i.relname AS index_name,
        t.relname AS table_name,
        ix.indisvalid AS is_valid,
        pg_get_indexdef(ix.indexrelid) AS index_def
      FROM pg_index ix
      JOIN pg_class i ON i.oid = ix.indexrelid
      JOIN pg_class t ON t.oid = ix.indrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = 'public' AND t.relname = 'investigations';
    `,
    5000
  )) as Array<{ index_name?: string; table_name?: string; is_valid?: boolean; index_def?: string }>;

  const indexMap = new Map<string, { isValid: boolean; def: string }>();
  for (const idx of indexes || []) {
    if (idx?.index_name) {
      indexMap.set(idx.index_name.toLowerCase(), {
        isValid: Boolean(idx.is_valid),
        def: idx.index_def || "",
      });
    }
  }

  // Check idx_investigations_created_at
  const createdAtIdx = indexMap.get("idx_investigations_created_at");
  if (!createdAtIdx) {
    errors.push("Missing required index: 'idx_investigations_created_at'");
  } else {
    if (!createdAtIdx.isValid) {
      errors.push("Index 'idx_investigations_created_at' exists but is invalid (indisvalid=false)");
    }
    const createdColClause = createdAtIdx.def.replace(/^[^(]+\(/, "(");
    if (!/\bcreated_at\s+desc\b/i.test(createdColClause)) {
      errors.push(
        `Index 'idx_investigations_created_at' definition mismatch: expected sort direction (created_at DESC), found '${createdAtIdx.def}'`
      );
    }
  }

  // Check idx_investigations_original_url
  const origUrlIdx = indexMap.get("idx_investigations_original_url");
  if (!origUrlIdx) {
    errors.push("Missing required index: 'idx_investigations_original_url'");
  } else {
    if (!origUrlIdx.isValid) {
      errors.push("Index 'idx_investigations_original_url' exists but is invalid (indisvalid=false)");
    }
    const origColClause = origUrlIdx.def.replace(/^[^(]+\(/, "(");
    if (!/\boriginal_url\b/i.test(origColClause)) {
      errors.push(
        `Index 'idx_investigations_original_url' definition mismatch: expected column (original_url), found '${origUrlIdx.def}'`
      );
    }
  }

  // 4. Check for same-name index conflicts on other tables in public schema
  const foreignIndexes = (await withTimeout(
    sql`
      SELECT
        i.relname AS index_name,
        t.relname AS table_name
      FROM pg_index ix
      JOIN pg_class i ON i.oid = ix.indexrelid
      JOIN pg_class t ON t.oid = ix.indrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = 'public'
        AND i.relname IN ('idx_investigations_created_at', 'idx_investigations_original_url')
        AND t.relname != 'investigations';
    `,
    5000
  )) as Array<{ index_name?: string; table_name?: string }>;

  for (const fi of foreignIndexes || []) {
    if (fi?.index_name && fi?.table_name) {
      errors.push(
        `Index name collision: '${fi.index_name}' exists on unrelated table '${fi.table_name}' in schema 'public'`
      );
    }
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Initializes the AheadGuard PostgreSQL schema on Neon if not already present.
 * Uses a dedicated, session-capable connection with PostgreSQL advisory locking (key 7429103)
 * to serialize concurrent migration runners and prevent DDL race conditions.
 *
 * Concurrency & Locking Architecture:
 * - Employs a single dedicated PostgreSQL session (Client) over WebSockets.
 * - Enforces lock_timeout (5000ms) and statement_timeout (10000ms) on the session.
 * - Acquires session advisory lock pg_advisory_lock(7429103) on this dedicated session.
 * - If the table exists, pre-validates schema BEFORE attempting any mutations.
 * - If incompatible, aborts with 0 mutations.
 * - If the table does not exist, provisions table, then provisions indexes.
 * - Followed by comprehensive schema, constraint, and index validation.
 * - Releases the advisory lock on the same session and closes the connection in finally.
 *
 * @param customSession - Optional session client or query function instance for isolated testing
 */
export async function initDatabaseSchema(
  customSession?: SessionQueryClient | TaggedQueryFunction | NeonQueryFunction<false, false>
): Promise<{ ok: boolean; error?: string }> {
  let client: SessionQueryClient | null = null;
  let sql: TaggedQueryFunction;
  let isConnected = false;
  let lockAcquired = false;

  try {
    if (typeof customSession === "function") {
      // Direct query function mock (used in isolated unit tests)
      sql = customSession as TaggedQueryFunction;
    } else if (customSession && typeof customSession === "object" && typeof customSession.query === "function") {
      // Custom session-capable client mock
      client = customSession;
      sql = createSessionSql(customSession);
    } else {
      // Production path: Create a dedicated session client over WebSockets
      if (!isDatabaseConfigured()) {
        return { ok: false, error: "Neon DATABASE_URL is not configured." };
      }
      ensureWebSocketConfigured();
      client = new Client({ connectionString: process.env.DATABASE_URL }) as unknown as SessionQueryClient;
      sql = createSessionSql(client);
    }

    if (client && typeof client.connect === "function") {
      // Connection timeout: 5000ms
      await withTimeout(client.connect(), 5000);
      isConnected = true;
    }

    try {
      // 1. Session Timeouts: Set bounded lock_timeout (5000ms) and statement_timeout (10000ms) on this session
      await withTimeout(sql`SET lock_timeout = '5000ms';`, 5000);
      await withTimeout(sql`SET statement_timeout = '10000ms';`, 5000);

      // 2. Lock Acquisition: Acquire session-level advisory lock (key 7429103) on this dedicated session
      await withTimeout(sql`SELECT pg_advisory_lock(7429103);`, 5500);
      lockAcquired = true;

      // 3. Existence Check: Check if table investigations already exists
      const tableCheck = (await withTimeout(
        sql`
          SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'investigations'
          ) AS table_exists;
        `,
        5000
      )) as Array<{ table_exists?: boolean | string }>;

      const tableExists = Boolean(
        tableCheck?.[0]?.table_exists === true ||
        tableCheck?.[0]?.table_exists === "t" ||
        tableCheck?.[0]?.table_exists === "true"
      );

      if (tableExists) {
        // Table exists: Pre-validate table structure FIRST before any DDL/mutation
        const structureVal = await validateTableStructure(sql);
        if (!structureVal.ok) {
          return {
            ok: false,
            error: `Schema drift detected: ${structureVal.errors.join("; ")}. Non-destructive schema reconciliation required.`,
          };
        }
      } else {
        // Table does not exist: Provision table
        await withTimeout(
          sql`
            CREATE TABLE IF NOT EXISTS investigations (
              id VARCHAR(64) PRIMARY KEY,
              original_url TEXT NOT NULL,
              final_url TEXT,
              risk_outcome VARCHAR(32) NOT NULL,
              threat_likelihood VARCHAR(32) NOT NULL,
              consequence_impact VARCHAR(32) NOT NULL,
              claimed_organization TEXT,
              analysis_mode VARCHAR(16) DEFAULT 'link',
              report_json JSONB NOT NULL,
              created_at TIMESTAMPTZ DEFAULT NOW()
            );
          `,
          10000
        );
      }

      // Provision required indexes idempotently
      await withTimeout(
        sql`
          CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations (created_at DESC);
        `,
        5000
      );

      await withTimeout(
        sql`
          CREATE INDEX IF NOT EXISTS idx_investigations_original_url ON investigations (original_url);
        `,
        5000
      );

      // Validate complete schema and index definitions
      const validation = await validateDatabaseSchema(sql);
      if (!validation.ok) {
        return {
          ok: false,
          error: `Schema drift detected: ${validation.errors.join("; ")}. Non-destructive schema reconciliation required.`,
        };
      }

      return { ok: true };
    } finally {
      if (lockAcquired) {
        try {
          await withTimeout(sql`SELECT pg_advisory_unlock(7429103);`, 5000);
        } catch {
          // Best-effort unlock; closing session automatically frees all session locks in PostgreSQL
        }
      }
    }
  } catch (err: unknown) {
    const raw = err instanceof Error ? err.message : String(err);
    const sanitized = raw.replace(/(?:postgres(?:ql)?:\/\/[^@\s]+@)[^\s]+/gi, "postgresql://[REDACTED]");
    return { ok: false, error: sanitized };
  } finally {
    if (client && typeof client.end === "function" && isConnected) {
      try {
        await withTimeout(client.end(), 5000);
      } catch {
        // Best-effort disconnect
      }
    }
  }
}

/**
 * Persists an investigation report to the Neon investigations table.
 * Automatically redacts sensitive query tokens, credentials, and PII before saving to at-rest storage.
 */
export async function saveInvestigation(report: InvestigationReport): Promise<{ ok: boolean; error?: string }> {
  if (!isDatabaseConfigured()) {
    return { ok: false, error: "Database not configured" };
  }

  try {
    const sql = getDb();

    // Privacy scrubbing: Sanitize URLs and text to avoid storing tokens or PII at rest
    const sanitizedReport = createShareableReport(report);
    const originalUrl = sanitizeUrlForSharing(report.originalUrl);
    const rawFinalUrl = report.observedDestination?.finalUrl || report.originalUrl;
    const finalUrl = sanitizeUrlForSharing(rawFinalUrl);
    const riskOutcome = report.riskOutcome;
    const threatLikelihood = report.threatLikelihood;
    const consequenceImpact = report.consequenceImpact;
    const claimedOrg = report.claimedOrganization || null;
    const analysisMode = report.analysisMode || "link";
    const reportJson = JSON.stringify(sanitizedReport);
    const validTimestamp = report.timestamp ? new Date(report.timestamp).toISOString() : new Date().toISOString();

    await withTimeout(
      sql`
        INSERT INTO investigations (
          id,
          original_url,
          final_url,
          risk_outcome,
          threat_likelihood,
          consequence_impact,
          claimed_organization,
          analysis_mode,
          report_json,
          created_at
        ) VALUES (
          ${report.investigationId},
          ${originalUrl},
          ${finalUrl},
          ${riskOutcome},
          ${threatLikelihood},
          ${consequenceImpact},
          ${claimedOrg},
          ${analysisMode},
          ${reportJson}::jsonb,
          ${validTimestamp}
        )
        ON CONFLICT (id) DO UPDATE SET
          risk_outcome = EXCLUDED.risk_outcome,
          threat_likelihood = EXCLUDED.threat_likelihood,
          consequence_impact = EXCLUDED.consequence_impact,
          report_json = EXCLUDED.report_json;
      `,
      5000
    );

    return { ok: true };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

/**
 * Fetches recent investigations from Neon (bounded and sanitized).
 */
export async function getRecentInvestigations(limit: number = 20): Promise<InvestigationReport[]> {
  if (!isDatabaseConfigured()) {
    return [];
  }

  // Bound limit strictly between 1 and 50
  const boundedLimit = Math.min(Math.max(1, Math.floor(limit)), 50);

  try {
    const sql = getDb();
    const rows = await withTimeout(
      sql`
        SELECT report_json
        FROM investigations
        ORDER BY created_at DESC
        LIMIT ${boundedLimit};
      `,
      5000
    );

    return rows.map((r) => {
      const row = r as { report_json: InvestigationReport | string };
      return typeof row.report_json === "string"
        ? (JSON.parse(row.report_json) as InvestigationReport)
        : row.report_json;
    });
  } catch {
    return [];
  }
}

/**
 * Fetches a single investigation report by its unique ID.
 * Returns null if not found or if database is unconfigured.
 */
export async function getInvestigationById(id: string): Promise<InvestigationReport | null> {
  if (!isDatabaseConfigured() || !id || typeof id !== "string") {
    return null;
  }

  // Strict identifier validation
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
    return null;
  }

  try {
    const sql = getDb();
    const rows = await withTimeout(
      sql`
        SELECT report_json
        FROM investigations
        WHERE id = ${id}
        LIMIT 1;
      `,
      5000
    );

    if (!rows || rows.length === 0) {
      return null;
    }

    const row = rows[0] as { report_json: InvestigationReport | string };
    return typeof row.report_json === "string"
      ? (JSON.parse(row.report_json) as InvestigationReport)
      : row.report_json;
  } catch {
    return null;
  }
}
