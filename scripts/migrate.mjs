#!/usr/bin/env node
/**
 * AheadGuard AI — Explicit Database Migration Runner
 *
 * Runs idempotent PostgreSQL schema migrations against the configured Neon database
 * using a dedicated, session-capable WebSocket connection (Client).
 *
 * Concurrency & Locking Architecture:
 * - Establishes a single dedicated PostgreSQL session via Neon Client over WebSockets.
 * - Exclusively requires MIGRATION_DATABASE_URL (direct Neon endpoint, no connection pooler).
 * - Rejects pooled endpoints (contains '-pooler' or 'pgbouncer=true') as pg_advisory_lock requires dedicated session state.
 * - Sets session lock_timeout ('5000ms') and statement_timeout ('10000ms').
 * - Acquires PostgreSQL session-level advisory lock (key 7429103) on this dedicated session.
 * - If public.investigations exists, pre-validates schema BEFORE attempting any mutations.
 * - If incompatible, aborts immediately with 0 mutations.
 * - If table does not exist, provisions table, then provisions indexes.
 * - Verifies complete schema, constraints, index definitions, and foreign index collisions.
 * - Releases the advisory lock on the same session in finally.
 * - Closes the session connection reliably.
 */
import { Client, neonConfig } from "@neondatabase/serverless";
import ws from "ws";
import { fileURLToPath } from "node:url";

neonConfig.webSocketConstructor = ws;

/**
 * Validates the migration database connection endpoint.
 *
 * Rules:
 * - Must be configured and non-empty.
 * - Must be a valid URI with scheme 'postgres:' or 'postgresql:'.
 * - Must NOT be a Neon pooled connection endpoint (must not contain '-pooler' or 'pgbouncer=true').
 *   Migrations require PostgreSQL session-level advisory locks (pg_advisory_lock), which are
 *   incompatible with pooled transaction-mode proxies. Direct connection endpoints are strictly required.
 * - Never leaks secrets, passwords, or credentials in validation error messages.
 *
 * @param {string | null | undefined} connectionString
 * @returns {{ valid: boolean; error?: string; hostname?: string }}
 */
export function validateMigrationEndpoint(connectionString) {
  if (!connectionString || typeof connectionString !== "string" || connectionString.trim().length === 0) {
    return {
      valid: false,
      error: "MIGRATION_DATABASE_URL environment variable is not configured. Dedicated direct connection string required for migrations.",
    };
  }

  let parsed;
  try {
    parsed = new URL(connectionString.trim());
  } catch {
    return {
      valid: false,
      error: "Invalid migration connection string: URI syntax is malformed.",
    };
  }

  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    return {
      valid: false,
      error: "Invalid migration connection string: scheme must be postgresql: or postgres:.",
    };
  }

  const isPoolerHost = parsed.hostname.toLowerCase().includes("-pooler");
  const hasPgBouncerParam = parsed.searchParams.get("pgbouncer") === "true";

  if (isPoolerHost || hasPgBouncerParam) {
    return {
      valid: false,
      error:
        "Incompatible migration endpoint: Neon pooled connection string detected (contains '-pooler' or 'pgbouncer=true'). Migrations require session-level advisory locking (pg_advisory_lock) and must use a direct endpoint without '-pooler'.",
    };
  }

  return {
    valid: true,
    hostname: parsed.hostname,
  };
}

/**
 * Preflight verification helper to establish whether direct migration endpoint
 * and application connection endpoint refer to the intended same database target.
 *
 * Rules:
 * 1. Validates migration URL with validateMigrationEndpoint().
 * 2. If appUrl is supplied, parses and validates appUrl URI structure and PostgreSQL scheme.
 * 3. Verifies that both URLs target the exact same database (database pathname must match).
 * 4. For Neon endpoints (*.neon.tech), verifies region and endpoint ID match:
 *    direct endpoint prefix must match pooled endpoint prefix without '-pooler'.
 * 5. For non-Neon endpoints, verifies hostname matches.
 * 6. If target mismatch detected, aborts with specific, actionable error.
 * 7. If appUrl is absent:
 *    - if requireTargetMatch === true: fails closed.
 *    - if requireTargetMatch === false: returns targetMatch: "uncompared" with an advisory warning.
 * 8. Never leaks credentials, passwords, or tokens in validation messages.
 *
 * @param {string | null | undefined} migrationUrl
 * @param {string | null | undefined} appUrl
 * @param {Object} [options]
 * @param {boolean} [options.requireTargetMatch]
 * @returns {{ valid: boolean; targetMatch?: boolean | "uncompared"; targetVerified?: boolean; hostname?: string; database?: string; error?: string; warning?: string }}
 */
export function verifyMigrationTargetIdentity(migrationUrl, appUrl, options = {}) {
  const migValidation = validateMigrationEndpoint(migrationUrl);
  if (!migValidation.valid || !migrationUrl) {
    return {
      valid: false,
      targetMatch: false,
      targetVerified: false,
      error: migValidation.error || "MIGRATION_DATABASE_URL is invalid.",
    };
  }

  let migParsed;
  try {
    migParsed = new URL(migrationUrl.trim());
  } catch {
    return {
      valid: false,
      targetMatch: false,
      targetVerified: false,
      error: "Invalid migration connection string: URI syntax is malformed.",
    };
  }

  const migHost = migParsed.hostname.toLowerCase();
  const migDb = migParsed.pathname.replace(/^\//, "").toLowerCase();

  // If application URL is not provided
  if (!appUrl || typeof appUrl !== "string" || appUrl.trim().length === 0) {
    if (options?.requireTargetMatch) {
      return {
        valid: false,
        targetMatch: false,
        targetVerified: false,
        error:
          "Target verification failed: application DATABASE_URL was not supplied for preflight comparison. Set requireTargetMatch to false or supply DATABASE_URL to compare.",
      };
    }
    return {
      valid: true,
      targetMatch: "uncompared",
      targetVerified: false,
      hostname: migHost,
      database: migDb,
      warning:
        "Application DATABASE_URL was not supplied for preflight target comparison. Operator must verify that MIGRATION_DATABASE_URL targets the intended database.",
    };
  }

  let appParsed;
  try {
    appParsed = new URL(appUrl.trim());
  } catch {
    return {
      valid: false,
      targetMatch: false,
      targetVerified: false,
      error: "Invalid application connection string: URI syntax is malformed.",
    };
  }

  if (appParsed.protocol !== "postgres:" && appParsed.protocol !== "postgresql:") {
    return {
      valid: false,
      targetMatch: false,
      targetVerified: false,
      error: "Invalid application connection string: scheme must be postgresql: or postgres:.",
    };
  }

  const appHost = appParsed.hostname.toLowerCase();
  const appDb = appParsed.pathname.replace(/^\//, "").toLowerCase();

  // Check database name match
  if (migDb !== appDb) {
    return {
      valid: false,
      targetMatch: false,
      targetVerified: false,
      error: `Migration target mismatch: MIGRATION_DATABASE_URL targets database '${migDb || "default"}' while application DATABASE_URL targets database '${appDb || "default"}'. Migration aborted to prevent modifying the wrong database.`,
    };
  }

  // Check Neon-specific project endpoint & region parity
  if (migHost.endsWith(".neon.tech") && appHost.endsWith(".neon.tech")) {
    const migParts = migHost.split(".");
    const appParts = appHost.split(".");

    const migSuffix = migParts.slice(1).join(".");
    const appSuffix = appParts.slice(1).join(".");
    if (migSuffix !== appSuffix) {
      return {
        valid: false,
        targetMatch: false,
        targetVerified: false,
        error: `Migration target mismatch: MIGRATION_DATABASE_URL region/domain ('${migSuffix}') does not match application DATABASE_URL region/domain ('${appSuffix}'). Migration aborted.`,
      };
    }

    const migPrefix = migParts[0];
    const appPrefix = appParts[0];
    const normalizedAppPrefix = appPrefix.endsWith("-pooler")
      ? appPrefix.slice(0, -"-pooler".length)
      : appPrefix;

    if (migPrefix !== normalizedAppPrefix) {
      return {
        valid: false,
        targetMatch: false,
        targetVerified: false,
        error: `Migration target mismatch: MIGRATION_DATABASE_URL endpoint ('${migPrefix}') does not match application DATABASE_URL pooled endpoint ('${appPrefix}'). Migration aborted.`,
      };
    }

    return {
      valid: true,
      targetMatch: true,
      targetVerified: true,
      hostname: migHost,
      database: migDb,
    };
  }

  // Generic non-Neon hosts
  if (migHost === appHost) {
    return {
      valid: true,
      targetMatch: true,
      targetVerified: true,
      hostname: migHost,
      database: migDb,
    };
  }

  return {
    valid: false,
    targetMatch: false,
    targetVerified: false,
    error: `Migration target mismatch: MIGRATION_DATABASE_URL host ('${migHost}') does not match application DATABASE_URL host ('${appHost}'). Migration aborted.`,
  };
}

export function withTimeout(promise, ms, desc = "Database operation") {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`${desc} timed out after ${ms}ms`));
    }, ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

export function createSessionSql(client) {
  return async (strings, ...values) => {
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

export const requiredColumns = {
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

export async function validateStructure(sql) {
  const errors = [];
  const columns = await sql`
    SELECT
      column_name,
      data_type,
      is_nullable
    FROM information_schema.columns
    WHERE table_name = 'investigations' AND table_schema = 'public';
  `;

  const colMap = new Map();
  for (const col of columns || []) {
    if (col?.column_name) {
      colMap.set(col.column_name.toLowerCase(), {
        dataType: (col.data_type || "").toLowerCase(),
        isNullable: (col.is_nullable || "").toUpperCase() === "YES",
      });
    }
  }

  for (const [colName, expected] of Object.entries(requiredColumns)) {
    const actual = colMap.get(colName);
    if (!actual) {
      errors.push(`Missing required column '${colName}'`);
    } else {
      if (actual.dataType !== expected.dataType) {
        errors.push(`Column '${colName}' data type mismatch: expected '${expected.dataType}', found '${actual.dataType}'`);
      }
      if (!expected.isNullable && actual.isNullable) {
        errors.push(`Column '${colName}' nullability mismatch: must be NOT NULL`);
      }
    }
  }

  const pks = await sql`
    SELECT kcu.column_name
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage kcu
      ON tc.constraint_name = kcu.constraint_name
      AND tc.table_schema = kcu.table_schema
    WHERE tc.constraint_type = 'PRIMARY KEY'
      AND tc.table_name = 'investigations'
      AND tc.table_schema = 'public';
  `;

  const pkCol = pks?.[0]?.column_name?.toLowerCase();
  if (pkCol !== "id") {
    errors.push(`Primary key mismatch on 'investigations': expected single primary key on 'id', found '${pkCol || "none"}'`);
  }

  return errors;
}

/**
 * Runs the database migration over a dedicated WebSocket session.
 *
 * @param {Object} [options]
 * @param {string} [options.connectionString] - Direct Neon connection string (defaults to process.env.MIGRATION_DATABASE_URL)
 * @param {string} [options.appConnectionString] - Optional application runtime connection string for target comparison (defaults to process.env.DATABASE_URL)
 * @param {boolean} [options.requireTargetMatch] - Whether to require verified match with application connection string
 * @returns {Promise<{ success: boolean; error?: string }>}
 */
export async function runMigration(options = {}) {
  const connectionString = options.connectionString || process.env.MIGRATION_DATABASE_URL;
  const appConnectionString = options.appConnectionString || process.env.DATABASE_URL;
  const requireTargetMatch =
    Boolean(options.requireTargetMatch) ||
    (typeof process !== "undefined" && process.argv?.includes("--require-target-match"));

  const preflight = verifyMigrationTargetIdentity(connectionString, appConnectionString, {
    requireTargetMatch,
  });

  if (!preflight.valid) {
    console.error(`Migration error: ${preflight.error}`);
    return { success: false, error: preflight.error };
  }

  const dbUrl = connectionString.trim();
  console.log("Starting AheadGuard PostgreSQL schema migration on Neon over dedicated session...");
  console.log(`Target database host: ${preflight.hostname}`);
  if (preflight.targetVerified) {
    console.log(
      `Target consistency confirmed: MIGRATION_DATABASE_URL matches application DATABASE_URL (${preflight.hostname}/${preflight.database}).`
    );
  } else if (preflight.warning) {
    console.warn(`Target preflight notice: ${preflight.warning}`);
  }

  const client = new Client({ connectionString: dbUrl });
  let isConnected = false;
  let lockAcquired = false;

  try {
    // 1. Database Connection Timeout: 5000ms
    console.log("Connecting to Neon PostgreSQL over dedicated WebSocket session...");
    await withTimeout(client.connect(), 5000, "Database connection");
    isConnected = true;

    const sql = createSessionSql(client);

    // 2. Session Timeouts: Set bounded lock_timeout (5000ms) and statement_timeout (10000ms) on this session
    console.log("Configuring session timeouts: lock_timeout=5000ms, statement_timeout=10000ms...");
    await withTimeout(sql`SET lock_timeout = '5000ms';`, 5000);
    await withTimeout(sql`SET statement_timeout = '10000ms';`, 5000);

    // 3. Session Advisory Lock: Acquire PostgreSQL session-level advisory lock (key 7429103)
    console.log("Acquiring PostgreSQL session advisory lock (key 7429103)...");
    await withTimeout(sql`SELECT pg_advisory_lock(7429103);`, 5500, "Advisory lock acquisition");
    lockAcquired = true;
    console.log("Session advisory lock acquired. Serialized migration execution in progress.");

    // 4. Existence Check: Check if table investigations already exists
    const tableCheck = await sql`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'investigations'
      ) AS table_exists;
    `;

    const tableExists = Boolean(
      tableCheck?.[0]?.table_exists === true ||
      tableCheck?.[0]?.table_exists === "t" ||
      tableCheck?.[0]?.table_exists === "true"
    );

    if (tableExists) {
      console.log("Table 'investigations' exists. Validating existing structure before applying any DDL/mutation...");
      const preErrors = await validateStructure(sql);
      if (preErrors.length > 0) {
        const errorMsg = `Pre-migration schema integrity verification failed:\n - ${preErrors.join("\n - ")}\nTable exists with incompatible schema. Aborting with 0 mutations.`;
        console.error(`Migration error: ${errorMsg}`);
        return { success: false, error: errorMsg };
      }
    } else {
      console.log("Table 'investigations' does not exist. Provisioning table...");
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
        10000,
        "Table creation"
      );
    }

    // Provision required indexes idempotently
    await withTimeout(
      sql`
        CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations (created_at DESC);
      `,
      5000,
      "Index creation (created_at)"
    );

    await withTimeout(
      sql`
        CREATE INDEX IF NOT EXISTS idx_investigations_original_url ON investigations (original_url);
      `,
      5000,
      "Index creation (original_url)"
    );

    console.log("Migration DDL complete. Validating full schema, constraints, and indexes...");

    const errors = await validateStructure(sql);

    // Validate index definitions on public.investigations
    const indexes = await sql`
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
    `;

    const indexMap = new Map();
    for (const idx of indexes || []) {
      if (idx?.index_name) {
        indexMap.set(idx.index_name.toLowerCase(), {
          isValid: Boolean(idx.is_valid),
          def: idx.index_def || "",
        });
      }
    }

    const createdAtIdx = indexMap.get("idx_investigations_created_at");
    if (!createdAtIdx) {
      errors.push("Missing required index: 'idx_investigations_created_at'");
    } else {
      if (!createdAtIdx.isValid) {
        errors.push("Index 'idx_investigations_created_at' exists but is invalid (indisvalid=false)");
      }
      const createdColClause = createdAtIdx.def.replace(/^[^(]+\(/, "(");
      if (!/\bcreated_at\s+desc\b/i.test(createdColClause)) {
        errors.push(`Index 'idx_investigations_created_at' definition mismatch: expected sort direction (created_at DESC), found '${createdAtIdx.def}'`);
      }
    }

    const origUrlIdx = indexMap.get("idx_investigations_original_url");
    if (!origUrlIdx) {
      errors.push("Missing required index: 'idx_investigations_original_url'");
    } else {
      if (!origUrlIdx.isValid) {
        errors.push("Index 'idx_investigations_original_url' exists but is invalid (indisvalid=false)");
      }
      const origColClause = origUrlIdx.def.replace(/^[^(]+\(/, "(");
      if (!/\boriginal_url\b/i.test(origColClause)) {
        errors.push(`Index 'idx_investigations_original_url' definition mismatch: expected column (original_url), found '${origUrlIdx.def}'`);
      }
    }

    // Validate foreign index collision in public schema
    const foreignIndexes = await sql`
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
    `;

    for (const fi of foreignIndexes || []) {
      if (fi?.index_name && fi?.table_name) {
        errors.push(`Index name collision: '${fi.index_name}' exists on unrelated table '${fi.table_name}' in schema 'public'`);
      }
    }

    if (errors.length > 0) {
      const errorMsg = `Schema integrity verification failed:\n - ${errors.join("\n - ")}\nNon-destructive manual schema reconciliation required.`;
      console.error(`Migration error: ${errorMsg}`);
      return { success: false, error: errorMsg };
    }

    console.log("Schema integrity verified: all required columns, data types, primary key, and index definitions are confirmed.");
    return { success: true };
  } catch (err) {
    const raw = err instanceof Error ? err.message : String(err);
    const sanitized = raw
      .replace(/(?:postgres(?:ql)?:\/\/[^@\s]+@)[^\s]+/gi, "postgresql://[REDACTED]")
      .replace(/postgres(?:ql)?:\/\/[^\s]+/gi, "postgresql://[REDACTED]");
    console.error("Migration error:", sanitized);
    return { success: false, error: sanitized };
  } finally {
    if (lockAcquired) {
      try {
        const sql = createSessionSql(client);
        await withTimeout(sql`SELECT pg_advisory_unlock(7429103);`, 5000);
        console.log("Session advisory lock released successfully.");
      } catch (unlockErr) {
        const unlockMsg = unlockErr instanceof Error ? unlockErr.message : String(unlockErr);
        console.warn("Notice: Session advisory unlock warning (session termination will free lock automatically):", unlockMsg);
      }
    }
    if (isConnected) {
      try {
        await withTimeout(client.end(), 5000);
        console.log("Database session closed.");
      } catch {
        // Best-effort close
      }
    }
  }
}

const isMain = () => {
  if (typeof process === "undefined" || !process.argv || !process.argv[1]) return false;
  try {
    const current = fileURLToPath(import.meta.url);
    const invoked = process.argv[1];
    return current === invoked || invoked.endsWith("migrate.mjs");
  } catch {
    return false;
  }
};

if (isMain()) {
  runMigration().then((result) => {
    if (!result?.success) {
      process.exit(1);
    }
  });
}
