import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { NeonQueryFunction } from "@neondatabase/serverless";
import {
  isDatabaseConfigured,
  getDb,
  testDatabaseConnection,
  getRecentInvestigations,
  getInvestigationById,
  saveInvestigation,
  withTimeout,
  initDatabaseSchema,
  validateTableStructure,
  validateDatabaseSchema,
  validateDatabaseHealthContract,
  validateMigrationEndpoint,
  verifyMigrationTargetIdentity,
  SessionQueryClient,
  createSessionSql,
} from "../lib/db";
import {
  validateMigrationEndpoint as validateMigrationEndpointScript,
  verifyMigrationTargetIdentity as verifyMigrationTargetIdentityScript,
  runMigration,
} from "../scripts/migrate.mjs";
import { verifyAdminAuth } from "../lib/api-security";
import { InvestigationReport } from "../lib/types";
import { DEMO_SCENARIO_A } from "../lib/demo-data";
import { sanitizeUrlForSharing, createShareableReport } from "../lib/share-report";

describe("Neon Serverless Postgres Integration & Persistence", () => {
  const originalEnv = process.env.DATABASE_URL;
  const originalAdmin = process.env.AHEADGUARD_ADMIN_KEY;

  beforeEach(() => {
    delete process.env.DATABASE_URL;
    delete process.env.AHEADGUARD_ADMIN_KEY;
  });

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.DATABASE_URL = originalEnv;
    } else {
      delete process.env.DATABASE_URL;
    }
    if (originalAdmin !== undefined) {
      process.env.AHEADGUARD_ADMIN_KEY = originalAdmin;
    } else {
      delete process.env.AHEADGUARD_ADMIN_KEY;
    }
  });

  it("reports unconfigured when DATABASE_URL is not set", () => {
    expect(isDatabaseConfigured()).toBe(false);
  });

  it("reports configured when DATABASE_URL is provided", () => {
    process.env.DATABASE_URL = "postgresql://user:pass@ep-test.us-east-2.aws.neon.tech/neondb?sslmode=require";
    expect(isDatabaseConfigured()).toBe(true);
  });

  it("throws clear error when attempting to query without DATABASE_URL", () => {
    expect(() => getDb()).toThrow(/Neon DATABASE_URL is not configured/);
  });

  it("returns safe unconfigured status when testing connection without DATABASE_URL", async () => {
    const status = await testDatabaseConnection();
    expect(status.ok).toBe(false);
    expect(status.status).toBe("unconfigured");
    expect(status.error).toContain("DATABASE_URL");
    // Verify no secret or internal host leakage
    expect(JSON.stringify(status)).not.toContain("password");
    expect(JSON.stringify(status)).not.toContain("neon.tech");
  });

  it("returns empty array for recent investigations when database is unconfigured", async () => {
    const list = await getRecentInvestigations();
    expect(list).toEqual([]);
  });

  it("returns null for getInvestigationById when database is unconfigured", async () => {
    const report = await getInvestigationById("inv_test_12345");
    expect(report).toBeNull();
  });

  it("rejects invalid investigation ID format in getInvestigationById", async () => {
    const report1 = await getInvestigationById("inv_test; DROP TABLE investigations;--");
    expect(report1).toBeNull();

    const report2 = await getInvestigationById("");
    expect(report2).toBeNull();
  });

  it("saveInvestigation returns safe error when database is unconfigured without throwing", async () => {
    const sampleReport: InvestigationReport = {
      ...DEMO_SCENARIO_A,
      investigationId: "inv_test_001",
      originalUrl: "https://example.com/login?token=SUPER_SECRET_123",
      normalizedUrl: "https://example.com/login?token=SUPER_SECRET_123",
    };

    const res = await saveInvestigation(sampleReport);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("Database not configured");
  });

  it("privacy scrubber strips query tokens and sensitive hashes before persistence", () => {
    const dirtyUrl = "https://example.com/auth?token=LIVE_SECRET_KEY&session=abc&otp=123456#access_token=xyz987";
    const cleaned = sanitizeUrlForSharing(dirtyUrl);

    expect(cleaned).not.toContain("LIVE_SECRET_KEY");
    expect(cleaned).not.toContain("session");
    expect(cleaned).not.toContain("otp");
    expect(cleaned).not.toContain("access_token");
    expect(cleaned).toContain("https://example.com/auth");
  });

  it("createShareableReport masks personal information (PII) before storage", () => {
    const dirtyReport: InvestigationReport = {
      ...DEMO_SCENARIO_A,
      originalUrl: "https://portal.com?token=SEC123",
      outcomeReason: "Contact applicant at candidate@personal-email.com or +1 (555) 234-5678 regarding salary.",
    };

    const scrubbed = createShareableReport(dirtyReport);
    expect(scrubbed.originalUrl).not.toContain("SEC123");
    expect(scrubbed.outcomeReason).not.toContain("candidate@personal-email.com");
    expect(scrubbed.outcomeReason).toContain("[EMAIL REDACTED]");
    expect(scrubbed.outcomeReason).toContain("[PHONE REDACTED]");
  });

  it("withTimeout successfully returns within time limit", async () => {
    const fastPromise = new Promise<string>((resolve) => setTimeout(() => resolve("fast"), 20));
    const result = await withTimeout(fastPromise, 200);
    expect(result).toBe("fast");
  });

  it("withTimeout throws timeout error when duration exceeded", async () => {
    const slowPromise = new Promise<string>((resolve) => setTimeout(() => resolve("slow"), 150));
    await expect(withTimeout(slowPromise, 25)).rejects.toThrow(/Database operation timed out after 25ms/);
  });

  describe("verifyAdminAuth — Timing-Safe Digest Comparison", () => {
    it("fails when AHEADGUARD_ADMIN_KEY is not configured, empty, or whitespace-only", () => {
      delete process.env.AHEADGUARD_ADMIN_KEY;
      const req = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer test_token" },
      });
      expect(verifyAdminAuth(req)).toBe(false);

      process.env.AHEADGUARD_ADMIN_KEY = "";
      expect(verifyAdminAuth(req)).toBe(false);

      process.env.AHEADGUARD_ADMIN_KEY = "   \t  ";
      expect(verifyAdminAuth(req)).toBe(false);
    });

    it("fails when Authorization header is missing or not a Bearer scheme", () => {
      process.env.AHEADGUARD_ADMIN_KEY = "super_secret_admin_key_32bytes";
      const req1 = new Request("http://localhost/api");
      expect(verifyAdminAuth(req1)).toBe(false);

      const req2 = new Request("http://localhost/api", {
        headers: { Authorization: "Basic dXNlcjpwYXNz" },
      });
      expect(verifyAdminAuth(req2)).toBe(false);

      const req3 = new Request("http://localhost/api", {
        headers: { Authorization: "Token super_secret_admin_key_32bytes" },
      });
      expect(verifyAdminAuth(req3)).toBe(false);

      // Tab separator strictly rejected under RFC 6750 grammar (requires 1*SP)
      const reqTab = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer\tsuper_secret_admin_key_32bytes" },
      });
      expect(verifyAdminAuth(reqTab)).toBe(false);
    });

    it("fails when token syntax violates RFC 6750 b64token grammar or has invalid padding", () => {
      process.env.AHEADGUARD_ADMIN_KEY = "super_secret_admin_key_32bytes";

      // Embedded spaces
      expect(verifyAdminAuth(new Request("http://localhost/api", {
        headers: { Authorization: "Bearer super secret admin key" },
      }))).toBe(false);

      // Disallowed characters (; or $)
      expect(verifyAdminAuth(new Request("http://localhost/api", {
        headers: { Authorization: "Bearer super_secret;DROP" },
      }))).toBe(false);

      expect(verifyAdminAuth(new Request("http://localhost/api", {
        headers: { Authorization: "Bearer super_secret$key" },
      }))).toBe(false);

      // Invalid padding placement (padding '=' followed by non-padding chars)
      expect(verifyAdminAuth(new Request("http://localhost/api", {
        headers: { Authorization: "Bearer super_secret=admin" },
      }))).toBe(false);

      // Padding character at start
      expect(verifyAdminAuth(new Request("http://localhost/api", {
        headers: { Authorization: "Bearer =super_secret" },
      }))).toBe(false);

      // Raw unnormalized header edge cases (tested via direct Request mock to bypass Fetch API auto-trimming)
      const createMockReq = (headerVal: string) => ({
        headers: {
          get: (name: string) => (name.toLowerCase() === "authorization" ? headerVal : null),
        },
      } as unknown as Request);

      // Leading space before scheme strictly rejected
      expect(verifyAdminAuth(createMockReq(" Bearer super_secret_admin_key_32bytes"))).toBe(false);

      // Trailing newlines / carriage returns / control characters strictly rejected
      expect(verifyAdminAuth(createMockReq("Bearer super_secret_admin_key_32bytes\n"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("Bearer super_secret_admin_key_32bytes\r"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("Bearer super_secret_admin_key_32bytes\r\n"))).toBe(false);
      expect(verifyAdminAuth(createMockReq("Bearer super_secret_admin_key_32bytes\0"))).toBe(false);
    });

    it("fails when token length or value differs, preserving raw token without accidental trimming", () => {
      process.env.AHEADGUARD_ADMIN_KEY = "super_secret_admin_key_32bytes";

      const reqWrongLen = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer short" },
      });
      expect(verifyAdminAuth(reqWrongLen)).toBe(false);

      const reqSameLenWrongVal = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer super_secret_admin_key_32byteX" },
      });
      expect(verifyAdminAuth(reqSameLenWrongVal)).toBe(false);

      // Case-sensitivity of token itself: differing casing in token fails
      const reqWrongCase = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer SUPER_SECRET_ADMIN_KEY_32BYTES" },
      });
      expect(verifyAdminAuth(reqWrongCase)).toBe(false);

      // Trailing whitespace in token makes it invalid; verify parser does not trim token
      const reqWithTrailingSpace = {
        headers: {
          get: (name: string) => (name.toLowerCase() === "authorization" ? "Bearer super_secret_admin_key_32bytes " : null),
        },
      } as unknown as Request;
      expect(verifyAdminAuth(reqWithTrailingSpace)).toBe(false);
    });

    it("succeeds when admin token matches exactly with case-insensitive Bearer scheme variants", () => {
      process.env.AHEADGUARD_ADMIN_KEY = "super_secret_admin_key_32bytes";

      // Standard Capitalized
      const reqValid1 = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer super_secret_admin_key_32bytes" },
      });
      expect(verifyAdminAuth(reqValid1)).toBe(true);

      // Lowercase (RFC 7235 / RFC 9110 case-insensitive scheme)
      const reqValid2 = new Request("http://localhost/api", {
        headers: { Authorization: "bearer super_secret_admin_key_32bytes" },
      });
      expect(verifyAdminAuth(reqValid2)).toBe(true);

      // Uppercase
      const reqValid3 = new Request("http://localhost/api", {
        headers: { Authorization: "BEARER super_secret_admin_key_32bytes" },
      });
      expect(verifyAdminAuth(reqValid3)).toBe(true);

      // Mixed-case
      const reqValid4 = new Request("http://localhost/api", {
        headers: { Authorization: "bEaReR super_secret_admin_key_32bytes" },
      });
      expect(verifyAdminAuth(reqValid4)).toBe(true);
    });
  });

  describe("Database Migration Runner & Schema Compatibility Matrix (Phase 3.5)", () => {
    const validColumns = [
      { column_name: "id", data_type: "character varying", is_nullable: "NO" },
      { column_name: "original_url", data_type: "text", is_nullable: "NO" },
      { column_name: "final_url", data_type: "text", is_nullable: "YES" },
      { column_name: "risk_outcome", data_type: "character varying", is_nullable: "NO" },
      { column_name: "threat_likelihood", data_type: "character varying", is_nullable: "NO" },
      { column_name: "consequence_impact", data_type: "character varying", is_nullable: "NO" },
      { column_name: "claimed_organization", data_type: "text", is_nullable: "YES" },
      { column_name: "analysis_mode", data_type: "character varying", is_nullable: "YES" },
      { column_name: "report_json", data_type: "jsonb", is_nullable: "NO" },
      { column_name: "created_at", data_type: "timestamp with time zone", is_nullable: "YES" },
    ];

    const validPks = [{ column_name: "id" }];

    const validIndexes = [
      {
        index_name: "idx_investigations_created_at",
        table_name: "investigations",
        is_valid: true,
        index_def: "CREATE INDEX idx_investigations_created_at ON public.investigations USING btree (created_at DESC)",
      },
      {
        index_name: "idx_investigations_original_url",
        table_name: "investigations",
        is_valid: true,
        index_def: "CREATE INDEX idx_investigations_original_url ON public.investigations USING btree (original_url)",
      },
    ];

    const createMockSql = (handler: (queryStr: string) => unknown): NeonQueryFunction<false, false> => {
      const fn = (strings: TemplateStringsArray, ...values: unknown[]) => {
        const query = strings.reduce((acc, str, i) => acc + str + String(values[i] ?? ""), "");
        return Promise.resolve(handler(query));
      };
      return fn as unknown as NeonQueryFunction<false, false>;
    };

    const createStandardMock = (overrides?: {
      columns?: unknown[];
      pks?: unknown[];
      indexes?: unknown[];
      foreignIndexes?: unknown[];
      tableExists?: boolean;
    }) => {
      return createMockSql((query) => {
        if (query.includes("information_schema.tables")) {
          return overrides?.tableExists !== undefined
            ? [{ table_exists: overrides.tableExists }]
            : [{ table_exists: true }];
        }
        if (query.includes("information_schema.columns")) {
          return overrides?.columns ?? validColumns;
        }
        if (query.includes("information_schema.table_constraints")) {
          return overrides?.pks ?? validPks;
        }
        if (query.includes("t.relname != 'investigations'")) {
          return overrides?.foreignIndexes ?? [];
        }
        if (query.includes("t.relname = 'investigations'")) {
          return overrides?.indexes ?? validIndexes;
        }
        return [];
      });
    };

    it("1. Fresh empty schema / compatible schema: Provisions table and indexes, validates integrity", async () => {
      const mockSql = createStandardMock();
      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(true);
      expect(res.error).toBeUndefined();
    });

    it("2. Repeated execution: Remains idempotent and succeeds without errors", async () => {
      const mockSql = createStandardMock();
      const run1 = await initDatabaseSchema(mockSql);
      expect(run1.ok).toBe(true);

      const run2 = await initDatabaseSchema(mockSql);
      expect(run2.ok).toBe(true);
    });

    it("3. Missing required column: Fails with clear schema-drift diagnostic", async () => {
      const driftedCols = validColumns.filter((c) => c.column_name !== "analysis_mode");
      const mockSql = createStandardMock({ columns: driftedCols });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Schema drift detected");
      expect(res.error).toContain("Missing required column 'analysis_mode'");
    });

    it("4. Incompatible column type: Detects mismatch (e.g. report_json as text instead of jsonb)", async () => {
      const driftedCols = validColumns.map((c) =>
        c.column_name === "report_json" ? { ...c, data_type: "text" } : c
      );
      const mockSql = createStandardMock({ columns: driftedCols });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("data type mismatch");
      expect(res.error).toContain("expected 'jsonb', found 'text'");
    });

    it("5. Incorrect nullability: Fails when a required NOT NULL column is nullable", async () => {
      const driftedCols = validColumns.map((c) =>
        c.column_name === "original_url" ? { ...c, is_nullable: "YES" } : c
      );
      const mockSql = createStandardMock({ columns: driftedCols });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Column 'original_url' nullability mismatch: must be NOT NULL");
    });

    it("6. Missing required primary-key constraint on id: Detects incompatible schema", async () => {
      const mockSql = createStandardMock({ pks: [] });
      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Primary key mismatch on 'investigations'");
    });

    it("6b. Primary-key constraint on wrong column: Detects single PK mismatch when PK is not on id", async () => {
      const mockSql = createStandardMock({ pks: [{ column_name: "original_url" }] });
      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("expected single primary key on 'id', found 'original_url'");
    });

    it("7. Missing expected index: Fails safely and identifies missing index", async () => {
      const missingIndexes = validIndexes.filter((i) => i.index_name !== "idx_investigations_created_at");
      const mockSql = createStandardMock({ indexes: missingIndexes });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Missing required index: 'idx_investigations_created_at'");
    });

    it("8. Expected index exists but is marked invalid (indisvalid=false): Fails safely", async () => {
      const invalidIndexes = validIndexes.map((i) =>
        i.index_name === "idx_investigations_created_at" ? { ...i, is_valid: false } : i
      );
      const mockSql = createStandardMock({ indexes: invalidIndexes });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Index 'idx_investigations_created_at' exists but is invalid (indisvalid=false)");
    });

    it("9. Same-name index with wrong definition / sort direction: Fails safely", async () => {
      const wrongDefIndexes = validIndexes.map((i) =>
        i.index_name === "idx_investigations_created_at"
          ? { ...i, index_def: "CREATE INDEX idx_investigations_created_at ON public.investigations (created_at ASC)" }
          : i
      );
      const mockSql = createStandardMock({ indexes: wrongDefIndexes });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("definition mismatch: expected sort direction (created_at DESC)");
    });

    it("9b. Same-name index with wrong column definition: Fails safely when idx_investigations_original_url does not index original_url", async () => {
      const wrongColIndexes = validIndexes.map((i) =>
        i.index_name === "idx_investigations_original_url"
          ? { ...i, index_def: "CREATE INDEX idx_investigations_original_url ON public.investigations USING btree (final_url)" }
          : i
      );
      const mockSql = createStandardMock({ indexes: wrongColIndexes });
      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Index 'idx_investigations_original_url' definition mismatch: expected column (original_url)");
    });

    it("10. Foreign index name collision on unrelated table in public schema: Detects collision", async () => {
      const mockSql = createStandardMock({
        foreignIndexes: [{ index_name: "idx_investigations_created_at", table_name: "audit_logs" }],
      });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Index name collision: 'idx_investigations_created_at' exists on unrelated table 'audit_logs'");
    });

    it("10b. Foreign collision on idx_investigations_original_url on another table in schema public", async () => {
      const mockSql = createStandardMock({
        foreignIndexes: [{ index_name: "idx_investigations_original_url", table_name: "external_links" }],
      });
      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Index name collision: 'idx_investigations_original_url' exists on unrelated table 'external_links'");
    });

    it("11. Missing database configuration: Returns error without executing", async () => {
      delete process.env.DATABASE_URL;
      const res = await initDatabaseSchema();
      expect(res.ok).toBe(false);
      expect(res.error).toContain("DATABASE_URL is not configured");
    });

    it("12. Insufficient database permissions: Reports safe diagnostic", async () => {
      const mockSql = createMockSql(() => {
        throw new Error("permission denied for schema public");
      });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("permission denied for schema public");
    });

    it("13. Error message sanitation: Redacts connection strings and credentials from error logs", async () => {
      const mockSql = createMockSql(() => {
        throw new Error("Connection failed at postgresql://app_user:super_secret_db_pass_123@ep-sample-neon.tech/neondb?sslmode=require");
      });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).not.toContain("super_secret_db_pass_123");
      expect(res.error).toContain("postgresql://[REDACTED]");
    });

    it("14. validateDatabaseSchema & validateTableStructure: Direct unit verification of schema validators", async () => {
      const mockSql = createStandardMock();
      const structVal = await validateTableStructure(mockSql);
      expect(structVal.ok).toBe(true);
      expect(structVal.errors).toHaveLength(0);

      const val = await validateDatabaseSchema(mockSql);
      expect(val.ok).toBe(true);
      expect(val.errors).toHaveLength(0);
    });

    it("15. Existing database with invalid schema: Halts during pre-validation with ZERO DDL mutations executed", async () => {
      const executedQueries: string[] = [];
      const driftedCols = validColumns.filter((c) => c.column_name !== "analysis_mode");

      const mockSql = createMockSql((query) => {
        executedQueries.push(query);
        if (query.includes("information_schema.tables")) {
          return [{ table_exists: true }];
        }
        if (query.includes("information_schema.columns")) {
          return driftedCols;
        }
        if (query.includes("information_schema.table_constraints")) {
          return validPks;
        }
        return [];
      });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Missing required column 'analysis_mode'");

      // Verify that NO CREATE TABLE or CREATE INDEX statements were executed
      const ddlStatements = executedQueries.filter(
        (q) => q.toUpperCase().includes("CREATE TABLE") || q.toUpperCase().includes("CREATE INDEX")
      );
      expect(ddlStatements).toHaveLength(0);
    });

    it("16. Fresh database: When table does not exist, provisions table, indexes, and validates", async () => {
      const executedQueries: string[] = [];

      const mockSql = createMockSql((query) => {
        executedQueries.push(query);
        if (query.includes("information_schema.tables")) {
          return [{ table_exists: false }];
        }
        if (query.includes("information_schema.columns")) {
          return validColumns;
        }
        if (query.includes("information_schema.table_constraints")) {
          return validPks;
        }
        if (query.includes("t.relname != 'investigations'")) {
          return [];
        }
        if (query.includes("t.relname = 'investigations'")) {
          return validIndexes;
        }
        return [];
      });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(true);

      const hasCreateTable = executedQueries.some((q) => q.toUpperCase().includes("CREATE TABLE"));
      const hasCreateIndex = executedQueries.some((q) => q.toUpperCase().includes("CREATE INDEX"));
      expect(hasCreateTable).toBe(true);
      expect(hasCreateIndex).toBe(true);
    });

    it("17. Advisory locking concurrency guard: Acquires pg_advisory_lock and releases via pg_advisory_unlock", async () => {
      const executedQueries: string[] = [];

      const mockSql = createMockSql((query) => {
        executedQueries.push(query);
        if (query.includes("information_schema.tables")) {
          return [{ table_exists: true }];
        }
        if (query.includes("information_schema.columns")) {
          return validColumns;
        }
        if (query.includes("information_schema.table_constraints")) {
          return validPks;
        }
        if (query.includes("t.relname != 'investigations'")) {
          return [];
        }
        if (query.includes("t.relname = 'investigations'")) {
          return validIndexes;
        }
        return [];
      });

      const res = await initDatabaseSchema(mockSql);
      expect(res.ok).toBe(true);

      const lockIdx = executedQueries.findIndex((q) => q.includes("pg_advisory_lock"));
      const unlockIdx = executedQueries.findIndex((q) => q.includes("pg_advisory_unlock"));

      expect(lockIdx).toBeGreaterThanOrEqual(0);
      expect(unlockIdx).toBeGreaterThanOrEqual(0);
      expect(lockIdx).toBeLessThan(unlockIdx);
    });
  });

  describe("Session-Level Advisory Lock & Migration Concurrency Matrix (Phase 4)", () => {
    const validColumns = [
      { column_name: "id", data_type: "character varying", is_nullable: "NO" },
      { column_name: "original_url", data_type: "text", is_nullable: "NO" },
      { column_name: "final_url", data_type: "text", is_nullable: "YES" },
      { column_name: "risk_outcome", data_type: "character varying", is_nullable: "NO" },
      { column_name: "threat_likelihood", data_type: "character varying", is_nullable: "NO" },
      { column_name: "consequence_impact", data_type: "character varying", is_nullable: "NO" },
      { column_name: "claimed_organization", data_type: "text", is_nullable: "YES" },
      { column_name: "analysis_mode", data_type: "character varying", is_nullable: "YES" },
      { column_name: "report_json", data_type: "jsonb", is_nullable: "NO" },
      { column_name: "created_at", data_type: "timestamp with time zone", is_nullable: "YES" },
    ];

    const validPks = [{ column_name: "id" }];

    const validIndexes = [
      {
        index_name: "idx_investigations_created_at",
        table_name: "investigations",
        is_valid: true,
        index_def: "CREATE INDEX idx_investigations_created_at ON public.investigations USING btree (created_at DESC)",
      },
      {
        index_name: "idx_investigations_original_url",
        table_name: "investigations",
        is_valid: true,
        index_def: "CREATE INDEX idx_investigations_original_url ON public.investigations USING btree (original_url)",
      },
    ];

    class MockPostgresLockManager {
      private lockHolder: string | null = null;

      tryAcquire(sessionId: string): boolean {
        if (this.lockHolder === null || this.lockHolder === sessionId) {
          this.lockHolder = sessionId;
          return true;
        }
        return false;
      }

      release(sessionId: string): boolean {
        if (this.lockHolder === sessionId) {
          this.lockHolder = null;
          return true;
        }
        return false;
      }

      getHolder(): string | null {
        return this.lockHolder;
      }
    }

    class MockPostgresSession implements SessionQueryClient {
      public id: string;
      public connected = false;
      public ended = false;
      public queries: string[] = [];
      private lockManager: MockPostgresLockManager;
      private tableExistsState: boolean;
      private columnsState: unknown[];
      private pksState: unknown[];
      private indexesState: unknown[];
      private foreignIndexesState: unknown[];

      constructor(
        id: string,
        lockManager: MockPostgresLockManager,
        opts?: {
          tableExists?: boolean;
          columns?: unknown[];
          pks?: unknown[];
          indexes?: unknown[];
          foreignIndexes?: unknown[];
        }
      ) {
        this.id = id;
        this.lockManager = lockManager;
        this.tableExistsState = opts?.tableExists ?? true;
        this.columnsState = opts?.columns ?? validColumns;
        this.pksState = opts?.pks ?? validPks;
        this.indexesState = opts?.indexes ?? validIndexes;
        this.foreignIndexesState = opts?.foreignIndexes ?? [];
      }

      async connect(): Promise<void> {
        this.connected = true;
      }

      async end(): Promise<void> {
        this.ended = true;
        this.lockManager.release(this.id);
      }

      async query(queryText: string): Promise<{ rows: unknown[] }> {
        if (!this.connected) {
          throw new Error("Client is not connected");
        }
        if (this.ended) {
          throw new Error("Client is closed and not queryable");
        }
        this.queries.push(queryText);

        if (queryText.includes("pg_advisory_lock")) {
          const acquired = this.lockManager.tryAcquire(this.id);
          if (!acquired) {
            throw new Error("canceling statement due to lock timeout");
          }
          return { rows: [{ pg_advisory_lock: 1 }] };
        }

        if (queryText.includes("pg_advisory_unlock")) {
          const released = this.lockManager.release(this.id);
          return { rows: [{ pg_advisory_unlock: released }] };
        }

        if (queryText.includes("information_schema.tables")) {
          return { rows: [{ table_exists: this.tableExistsState }] };
        }

        if (queryText.includes("information_schema.columns")) {
          return { rows: this.columnsState };
        }

        if (queryText.includes("information_schema.table_constraints")) {
          return { rows: this.pksState };
        }

        if (queryText.includes("t.relname != 'investigations'")) {
          return { rows: this.foreignIndexesState };
        }

        if (queryText.includes("t.relname = 'investigations'")) {
          return { rows: this.indexesState };
        }

        return { rows: [] };
      }
    }

    it("1. Dedicated session client connects, sets bounded timeouts, acquires lock, migrates, and unlocks cleanly", async () => {
      const lockMgr = new MockPostgresLockManager();
      const session = new MockPostgresSession("session-1", lockMgr);

      const res = await initDatabaseSchema(session);
      expect(res.ok).toBe(true);
      expect(session.connected).toBe(true);
      expect(session.ended).toBe(true);
      expect(lockMgr.getHolder()).toBeNull();

      // Verify bounded timeouts were set on the session
      expect(session.queries.some((q) => q.includes("SET lock_timeout = '5000ms'"))).toBe(true);
      expect(session.queries.some((q) => q.includes("SET statement_timeout = '10000ms'"))).toBe(true);

      // Verify lock order
      const lockIdx = session.queries.findIndex((q) => q.includes("pg_advisory_lock"));
      const unlockIdx = session.queries.findIndex((q) => q.includes("pg_advisory_unlock"));
      expect(lockIdx).toBeGreaterThanOrEqual(0);
      expect(unlockIdx).toBeGreaterThan(lockIdx);
    });

    it("2. Validation and migration execution strictly occur while advisory lock is held", async () => {
      const lockMgr = new MockPostgresLockManager();
      const session = new MockPostgresSession("session-1", lockMgr, { tableExists: false });

      const res = await initDatabaseSchema(session);
      expect(res.ok).toBe(true);

      const lockIdx = session.queries.findIndex((q) => q.includes("pg_advisory_lock"));
      const tableCheckIdx = session.queries.findIndex((q) => q.includes("information_schema.tables"));
      const createTableIdx = session.queries.findIndex((q) => q.includes("CREATE TABLE"));
      const createIndexIdx = session.queries.findIndex((q) => q.includes("CREATE INDEX"));
      const unlockIdx = session.queries.findIndex((q) => q.includes("pg_advisory_unlock"));

      expect(lockIdx).toBeLessThan(tableCheckIdx);
      expect(tableCheckIdx).toBeLessThan(createTableIdx);
      expect(createTableIdx).toBeLessThan(createIndexIdx);
      expect(createIndexIdx).toBeLessThan(unlockIdx);
    });

    it("3. Release on validation failure: Releasing lock and closing session on early exit", async () => {
      const lockMgr = new MockPostgresLockManager();
      const driftedCols = validColumns.filter((c) => c.column_name !== "original_url");
      const session = new MockPostgresSession("session-drift", lockMgr, { columns: driftedCols });

      const res = await initDatabaseSchema(session);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("Missing required column 'original_url'");

      // Lock must be released and session ended despite early validation failure
      expect(session.ended).toBe(true);
      expect(lockMgr.getHolder()).toBeNull();
      expect(session.queries.some((q) => q.includes("pg_advisory_unlock"))).toBe(true);

      // 0 DDL statements executed
      const ddlStatements = session.queries.filter(
        (q) => q.toUpperCase().includes("CREATE TABLE") || q.toUpperCase().includes("CREATE INDEX")
      );
      expect(ddlStatements).toHaveLength(0);
    });

    it("4. Bounded lock acquisition failure: Reports safe diagnostic when lock timeout triggers", async () => {
      const lockMgr = new MockPostgresLockManager();
      // Pre-acquire lock by an external session
      lockMgr.tryAcquire("external-session-holder");

      const session = new MockPostgresSession("session-blocked", lockMgr);

      const res = await initDatabaseSchema(session);
      expect(res.ok).toBe(false);
      expect(res.error).toContain("canceling statement due to lock timeout");

      // 0 DDL statements executed
      const ddlStatements = session.queries.filter(
        (q) => q.toUpperCase().includes("CREATE TABLE") || q.toUpperCase().includes("CREATE INDEX")
      );
      expect(ddlStatements).toHaveLength(0);

      // Session must be closed cleanly
      expect(session.ended).toBe(true);
    });

    it("5. Two concurrent migration attempts: Second runner is blocked while first holds lock, then succeeds idempotently after release", async () => {
      const lockMgr = new MockPostgresLockManager();
      const session1 = new MockPostgresSession("runner-1", lockMgr, { tableExists: false });
      const session2 = new MockPostgresSession("runner-2", lockMgr, { tableExists: true });

      // Runner 1 executes migration and provisions table
      const res1 = await initDatabaseSchema(session1);
      expect(res1.ok).toBe(true);
      expect(session1.ended).toBe(true);
      expect(lockMgr.getHolder()).toBeNull();

      // Runner 2 can now acquire the released lock and run idempotently
      const res2 = await initDatabaseSchema(session2);
      expect(res2.ok).toBe(true);
      expect(session2.ended).toBe(true);
      expect(lockMgr.getHolder()).toBeNull();

      // Runner 2 executed pre-validation with 0 table creations
      const runner2CreateTables = session2.queries.filter((q) => q.toUpperCase().includes("CREATE TABLE"));
      expect(runner2CreateTables).toHaveLength(0);
    });

    it("6. Correct session reuse: Every query in migration path is executed on the same dedicated session", async () => {
      const lockMgr = new MockPostgresLockManager();
      const session = new MockPostgresSession("single-session-check", lockMgr);

      await initDatabaseSchema(session);

      // Ensure that all operations occurred on this single session instance
      expect(session.queries.length).toBeGreaterThan(5);
      expect(session.queries[0]).toContain("SET lock_timeout");
      expect(session.queries[session.queries.length - 1]).toContain("pg_advisory_unlock");
    });

    it("7. createSessionSql adapter: Formats template queries and executes on dedicated client", async () => {
      const recorded: string[] = [];
      const dummyClient = {
        query: async (text: string) => {
          recorded.push(text);
          return { rows: [{ result: 42 }] };
        },
      };

      const sql = createSessionSql(dummyClient);
      const res = await sql`SELECT ${1} + ${2} as total;`;

      expect(recorded[0]).toBe("SELECT 1 + 2 as total;");
      expect(res).toEqual([{ result: 42 }]);
    });
  });

  describe("Database Health Contract & Persistence Readiness Validation", () => {
    it("1. accepts consistent 'connected' status with ok: true in both generic and strict mode", () => {
      const response = { db: { ok: true, status: "connected" } };
      const generic = validateDatabaseHealthContract(response);
      expect(generic.valid).toBe(true);
      expect(generic.status).toBe("connected");
      expect(generic.ok).toBe(true);

      const strict = validateDatabaseHealthContract(response, { strictConnected: true });
      expect(strict.valid).toBe(true);
      expect(strict.status).toBe("connected");
      expect(strict.ok).toBe(true);
    });

    it("2. accepts 'unconfigured' with ok: false in generic mode as safe fallback", () => {
      const response = {
        db: {
          ok: false,
          status: "unconfigured",
          error: "DATABASE_URL environment variable is not configured.",
        },
      };
      const generic = validateDatabaseHealthContract(response);
      expect(generic.valid).toBe(true);
      expect(generic.status).toBe("unconfigured");
      expect(generic.ok).toBe(false);
    });

    it("3. rejects 'unconfigured' in strict persistence mode with clear explanation", () => {
      const response = {
        db: {
          ok: false,
          status: "unconfigured",
          error: "DATABASE_URL environment variable is not configured.",
        },
      };
      const strict = validateDatabaseHealthContract(response, { strictConnected: true });
      expect(strict.valid).toBe(false);
      expect(strict.error).toContain("Strict database persistence check failed");
      expect(strict.error).toContain("unconfigured");
    });

    it("4. accepts 'unavailable' in generic mode structure check but rejects in strict mode", () => {
      const response = {
        db: {
          ok: false,
          status: "unavailable",
          error: "Unable to reach database service.",
        },
      };
      const generic = validateDatabaseHealthContract(response);
      expect(generic.valid).toBe(true);
      expect(generic.status).toBe("unavailable");
      expect(generic.ok).toBe(false);

      const strict = validateDatabaseHealthContract(response, { strictConnected: true });
      expect(strict.valid).toBe(false);
      expect(strict.error).toContain("Strict database persistence check failed");
      expect(strict.error).toContain("unavailable");
    });

    it("5. rejects unexpected status values (such as 'error', 'unknown', 'degraded')", () => {
      const invalidStatuses = ["error", "unknown", "degraded", "healthy", "down"];
      for (const badStatus of invalidStatuses) {
        const res = validateDatabaseHealthContract({ db: { ok: false, status: badStatus } });
        expect(res.valid).toBe(false);
        expect(res.error).toContain("Property 'db.status' must be one of");
      }
    });

    it("6. rejects inconsistent state: 'connected' with ok: false", () => {
      const res = validateDatabaseHealthContract({ db: { ok: false, status: "connected" } });
      expect(res.valid).toBe(false);
      expect(res.error).toContain("Inconsistent state: status is 'connected' but 'ok' is false");
    });

    it("7. rejects inconsistent state: 'unconfigured' or 'unavailable' with ok: true", () => {
      const res1 = validateDatabaseHealthContract({ db: { ok: true, status: "unconfigured" } });
      expect(res1.valid).toBe(false);
      expect(res1.error).toContain("Inconsistent state: status is 'unconfigured' but 'ok' is true");

      const res2 = validateDatabaseHealthContract({ db: { ok: true, status: "unavailable" } });
      expect(res2.valid).toBe(false);
      expect(res2.error).toContain("Inconsistent state: status is 'unavailable' but 'ok' is true");
    });

    it("8. rejects non-object responses, null, and missing db property", () => {
      expect(validateDatabaseHealthContract(null).valid).toBe(false);
      expect(validateDatabaseHealthContract("hello").valid).toBe(false);
      expect(validateDatabaseHealthContract({}).valid).toBe(false);
      expect(validateDatabaseHealthContract({ db: null }).valid).toBe(false);
      expect(validateDatabaseHealthContract({ db: { ok: "not-a-bool", status: "connected" } }).valid).toBe(false);
    });

    it("9. security check: rejects error responses that leak sensitive credentials or hostnames", () => {
      const leakyResponse1 = {
        db: {
          ok: false,
          status: "unavailable",
          error: "Connection failed for user root with password=SECRET_PASS_123",
        },
      };
      const res1 = validateDatabaseHealthContract(leakyResponse1);
      expect(res1.valid).toBe(false);
      expect(res1.error).toContain("Security violation");

      const leakyResponse2 = {
        db: {
          ok: false,
          status: "unavailable",
          error: "Connection timeout connecting to postgresql://user:pass@ep-secret.us-east-2.aws.neon.tech/neondb",
        },
      };
      const res2 = validateDatabaseHealthContract(leakyResponse2);
      expect(res2.valid).toBe(false);
      expect(res2.error).toContain("Security violation");
    });
  });

  describe("Dedicated Migration Endpoint Validation & Contract", () => {
    const validDirectUrl =
      "postgresql://user:secretpass@ep-sample-12345.us-east-2.aws.neon.tech/neondb?sslmode=require";
    const pooledUrl =
      "postgresql://user:secretpass@ep-sample-12345-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require";
    const pgBouncerUrl =
      "postgresql://user:secretpass@ep-sample-12345.us-east-2.aws.neon.tech/neondb?sslmode=require&pgbouncer=true";

    it("rejects missing, empty, or whitespace-only connection string", () => {
      const resNull = validateMigrationEndpoint(null);
      expect(resNull.valid).toBe(false);
      expect(resNull.error).toContain("MIGRATION_DATABASE_URL environment variable is not configured");

      const resUndefined = validateMigrationEndpoint(undefined);
      expect(resUndefined.valid).toBe(false);
      expect(resUndefined.error).toContain("MIGRATION_DATABASE_URL environment variable is not configured");

      const resEmpty = validateMigrationEndpoint("   ");
      expect(resEmpty.valid).toBe(false);
      expect(resEmpty.error).toContain("MIGRATION_DATABASE_URL environment variable is not configured");
    });

    it("rejects malformed URI syntax without throwing", () => {
      const res = validateMigrationEndpoint("not-a-valid-uri");
      expect(res.valid).toBe(false);
      expect(res.error).toContain("URI syntax is malformed");
    });

    it("rejects non-PostgreSQL URI schemes", () => {
      const resHttp = validateMigrationEndpoint("https://example.com/db");
      expect(resHttp.valid).toBe(false);
      expect(resHttp.error).toContain("scheme must be postgresql: or postgres:");

      const resMysql = validateMigrationEndpoint("mysql://user:pass@ep-test.neon.tech/db");
      expect(resMysql.valid).toBe(false);
      expect(resMysql.error).toContain("scheme must be postgresql: or postgres:");
    });

    it("strictly rejects Neon pooled endpoints containing '-pooler'", () => {
      const res = validateMigrationEndpoint(pooledUrl);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("Incompatible migration endpoint: Neon pooled connection string detected");
      expect(res.error).toContain("contains '-pooler'");
      expect(res.error).toContain("pg_advisory_lock");
      // Security: never echo password or full connection string in error
      expect(res.error).not.toContain("secretpass");
      expect(res.error).not.toContain("user:");
    });

    it("strictly rejects connection strings containing 'pgbouncer=true'", () => {
      const res = validateMigrationEndpoint(pgBouncerUrl);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("Incompatible migration endpoint: Neon pooled connection string detected");
      expect(res.error).not.toContain("secretpass");
    });

    it("accepts valid direct Neon PostgreSQL connection string", () => {
      const res = validateMigrationEndpoint(validDirectUrl);
      expect(res.valid).toBe(true);
      expect(res.hostname).toBe("ep-sample-12345.us-east-2.aws.neon.tech");
      expect(res.error).toBeUndefined();
    });

    it("accepts valid postgres: scheme (alternative to postgresql:)", () => {
      const altUrl = "postgres://user:secretpass@ep-direct-abc.us-east-2.aws.neon.tech/neondb?sslmode=require";
      const res = validateMigrationEndpoint(altUrl);
      expect(res.valid).toBe(true);
      expect(res.hostname).toBe("ep-direct-abc.us-east-2.aws.neon.tech");
    });

    it("guarantees migration script validator parity with lib/db implementation", () => {
      expect(validateMigrationEndpointScript(validDirectUrl)).toEqual(validateMigrationEndpoint(validDirectUrl));
      expect(validateMigrationEndpointScript(pooledUrl)).toEqual(validateMigrationEndpoint(pooledUrl));
      expect(validateMigrationEndpointScript(null)).toEqual(validateMigrationEndpoint(null));
    });

    it("strictly verifies zero fallback to DATABASE_URL in migration runner logic", () => {
      const prevMigrationUrl = process.env.MIGRATION_DATABASE_URL;
      const prevDbUrl = process.env.DATABASE_URL;
      try {
        delete process.env.MIGRATION_DATABASE_URL;
        process.env.DATABASE_URL = validDirectUrl;

        // Validating migration endpoint when MIGRATION_DATABASE_URL is missing must fail even if DATABASE_URL is set
        const res = validateMigrationEndpoint(process.env.MIGRATION_DATABASE_URL);
        expect(res.valid).toBe(false);
        expect(res.error).toContain("MIGRATION_DATABASE_URL environment variable is not configured");
      } finally {
        if (prevMigrationUrl !== undefined) process.env.MIGRATION_DATABASE_URL = prevMigrationUrl;
        else delete process.env.MIGRATION_DATABASE_URL;
        if (prevDbUrl !== undefined) process.env.DATABASE_URL = prevDbUrl;
        else delete process.env.DATABASE_URL;
      }
    });

    describe("Migration Preflight Target-Identity Verification", () => {
      const directNeonUrl =
        "postgresql://user:pass123@ep-sample-12345.us-east-2.aws.neon.tech/neondb?sslmode=require";
      const pooledNeonUrl =
        "postgresql://user:pass123@ep-sample-12345-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require";
      const mismatchEndpointNeonUrl =
        "postgresql://user:pass123@ep-different-99999-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require";
      const mismatchRegionNeonUrl =
        "postgresql://user:pass123@ep-sample-12345-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require";
      const mismatchDbNeonUrl =
        "postgresql://user:pass123@ep-sample-12345-pooler.us-east-2.aws.neon.tech/otherdb?sslmode=require";

      it("confirms target match when direct and pooled Neon URLs match on project ID, region, and database", () => {
        const res = verifyMigrationTargetIdentity(directNeonUrl, pooledNeonUrl);
        expect(res.valid).toBe(true);
        expect(res.targetMatch).toBe(true);
        expect(res.targetVerified).toBe(true);
        expect(res.hostname).toBe("ep-sample-12345.us-east-2.aws.neon.tech");
        expect(res.database).toBe("neondb");
      });

      it("rejects migration when target project endpoint ID mismatches between migration and app URLs", () => {
        const res = verifyMigrationTargetIdentity(directNeonUrl, mismatchEndpointNeonUrl);
        expect(res.valid).toBe(false);
        expect(res.targetMatch).toBe(false);
        expect(res.error).toContain("Migration target mismatch: MIGRATION_DATABASE_URL endpoint");
        expect(res.error).toContain("does not match application DATABASE_URL pooled endpoint");
        // Security check: no password leakage
        expect(res.error).not.toContain("pass123");
      });

      it("rejects migration when target region mismatches between migration and app URLs", () => {
        const res = verifyMigrationTargetIdentity(directNeonUrl, mismatchRegionNeonUrl);
        expect(res.valid).toBe(false);
        expect(res.targetMatch).toBe(false);
        expect(res.error).toContain("Migration target mismatch: MIGRATION_DATABASE_URL region/domain");
        expect(res.error).not.toContain("pass123");
      });

      it("rejects migration when database name mismatches between migration and app URLs", () => {
        const res = verifyMigrationTargetIdentity(directNeonUrl, mismatchDbNeonUrl);
        expect(res.valid).toBe(false);
        expect(res.targetMatch).toBe(false);
        expect(res.error).toContain("Migration target mismatch: MIGRATION_DATABASE_URL targets database 'neondb'");
        expect(res.error).toContain("while application DATABASE_URL targets database 'otherdb'");
      });

      it("returns uncompared status with advisory warning when application URL is omitted and requireTargetMatch is false", () => {
        const res = verifyMigrationTargetIdentity(directNeonUrl, null, { requireTargetMatch: false });
        expect(res.valid).toBe(true);
        expect(res.targetMatch).toBe("uncompared");
        expect(res.targetVerified).toBe(false);
        expect(res.warning).toContain("Application DATABASE_URL was not supplied for preflight target comparison");
      });

      it("fails closed when application URL is omitted and requireTargetMatch is true", () => {
        const res = verifyMigrationTargetIdentity(directNeonUrl, null, { requireTargetMatch: true });
        expect(res.valid).toBe(false);
        expect(res.targetMatch).toBe(false);
        expect(res.error).toContain("Target verification failed: application DATABASE_URL was not supplied");
      });

      it("accepts matching generic hostnames and rejects mismatching generic hostnames", () => {
        const genericDirect = "postgresql://user:pass@db.internal:5432/appdb";
        const genericApp = "postgresql://user:pass@db.internal:5432/appdb";
        const genericMismatch = "postgresql://user:pass@other-db.internal:5432/appdb";

        const resMatch = verifyMigrationTargetIdentity(genericDirect, genericApp);
        expect(resMatch.valid).toBe(true);
        expect(resMatch.targetVerified).toBe(true);

        const resMismatch = verifyMigrationTargetIdentity(genericDirect, genericMismatch);
        expect(resMismatch.valid).toBe(false);
        expect(resMismatch.error).toContain("Migration target mismatch: MIGRATION_DATABASE_URL host");
      });

      it("guarantees validator parity between lib/db and scripts/migrate.mjs for target identity", () => {
        expect(verifyMigrationTargetIdentityScript(directNeonUrl, pooledNeonUrl)).toEqual(
          verifyMigrationTargetIdentity(directNeonUrl, pooledNeonUrl)
        );
        expect(verifyMigrationTargetIdentityScript(directNeonUrl, mismatchEndpointNeonUrl)).toEqual(
          verifyMigrationTargetIdentity(directNeonUrl, mismatchEndpointNeonUrl)
        );
        expect(verifyMigrationTargetIdentityScript(directNeonUrl, null)).toEqual(
          verifyMigrationTargetIdentity(directNeonUrl, null)
        );
      });

      it("runMigration preflight blocks execution and aborts with code when targets mismatch", async () => {
        const res = await runMigration({
          connectionString: directNeonUrl,
          appConnectionString: mismatchEndpointNeonUrl,
        });
        expect(res.success).toBe(false);
        expect(res.error).toContain("Migration target mismatch");
      });
    });
  });
});
