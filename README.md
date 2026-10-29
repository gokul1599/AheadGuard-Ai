# AheadGuard AI — Pre-Action Digital Safety Guardian

> **Your AI checks first. You act with confidence.**

AheadGuard AI is a proactive digital safety guardian that investigates unknown destinations, phishing traps, and deceptive links **before** you commit sensitive actions. It deploys an isolated, read-only remote browser sandbox to inspect live behavior, evaluates observable evidence against a deterministic policy engine, simulates consequences with **Action Preview**, and maintains a privacy-first **Evidence Ledger**.

- **Deployed Production Dashboard**: [https://aheadguard-ai.vercel.app](https://aheadguard-ai.vercel.app)
- **GitHub Repository**: [https://github.com/gokul1599/AheadGuard-Ai](https://github.com/gokul1599/AheadGuard-Ai)

---

## Key Features

1. **Pre-Action Investigation Engine**:
   - Accepts public HTTP/HTTPS URLs or unstructured messages containing links.
   - Enforces an isolated, read-only browser session via TinyFish.
   - Inspects real-time redirects, DOM form inputs (password/credit card fields), permission prompts, and script activity.
   - Provides an auto-scrolling live terminal stream via Server-Sent Events (SSE).

2. **Deterministic 4-Tier Risk Policy**:
   - Classifies destinations strictly based on observable facts, never on speculative trust scores:
     - 🔴 **High risk**: Active credential phishing, deceptive lookalike domains, unauthenticated redirects, or high-risk input prompts.
     - 🟡 **Suspicious**: Lookalike heuristics, brand mismatch signals, or ambiguous unverified destinations.
     - 🟢 **Low observed risk**: Benign destination verified with no warning signals found in this probe (*"Notice: Low observed risk indicates no active warning signals were found during this probe. It is not an absolute guarantee of safety."*).
     - ⚪ **Unknown**: Destination could not be verified due to timeouts, network barriers, or unreachable targets.

3. **Action Preview ("Before You Commit")**:
   - Consequence simulation model detailing what would happen if a user proceeds.
   - Highlights proposed actions, consequences of proceeding, and specific risk factors.
   - Suggests a deterministic, safer alternative action (e.g., direct navigation via verified bookmarks).

4. **Evidence Explorer & Provenance**:
   - Strict separation between **Observed Facts** (direct sandbox observations) and **Model Interpretations** (clearly labeled AI inferences with confidence ratings).
   - Detailed evidence items with verifiable provenance badges (`TINYFISH_DOM`, `HTTP_ANALYSIS`, `NETWORK_REDIRECT`, etc.).

5. **Two-Tier Privacy & Evidence Architecture**:
   - **Browser-Local Evidence Ledger**: Client-side browsing history and session evidence stored locally in the user's browser via `localStorage` (`aheadguard_evidence_ledger_v1`). Users maintain autonomous privacy control with instant ledger wipe, pause/resume recording toggles, and zero tracking scripts. This client-side history is never automatically transmitted to third parties or centralized telemetry.
   - **Centralized Server-Side Persistence (Neon PostgreSQL)**: When the server administrator configures `DATABASE_URL`, server-side investigations executed via `/api/investigate` are safely recorded in Neon PostgreSQL (`public.investigations`) for centralized organizational security review. Centralized history is strictly protected behind `AHEADGUARD_ADMIN_KEY` using constant-time verification. When `DATABASE_URL` is omitted, the backend runs in ephemeral mode where investigations exist solely in memory for the duration of the request. Predefined demo scenarios and offline checks are never persisted.

6. **Chrome Extension (Manifest V3)**:
   - Configured out-of-the-box for production (`https://aheadguard-ai.vercel.app`).
   - Narrow host permissions restricted strictly to the official backend origin and localhost development.
   - Privacy-first design: **Zero broad content-script injections**. All tab and navigation awareness relies exclusively on native Chrome MV3 APIs (`activeTab`, `webNavigation`).
   - Real-time active tab detection with automatic filtering of internal (`chrome://`) schemes.
   - Collapsible manual URL checker, Action Preview, Evidence highlights, and "Return to Safety" navigation action.

---

## Security Architecture & Defenses

- **Strict Server-Side Isolation**: All external browser interactions occur inside an isolated remote sandbox. The investigator will never log in, submit forms, execute files, or follow instructions attempting to hijack the investigation.
- **SSRF & Loopback Defense**: Pre-flight validation blocks loopback (`127.0.0.1`, `localhost`), link-local (`169.254.0.0/16`), private RFC 1918 subnets, cloud metadata endpoints (`169.254.169.254`), and non-standard schemes (`javascript:`, `file:`, `data:`).
- **Redirect Chain Validation**: Follows redirection targets and re-evaluates `observed_final_url` against SSRF rules to prevent open-redirect escape attacks.
- **Strict Origin & CORS Allowlist**: 
  - Permits the exact production dashboard origin (`https://aheadguard-ai.vercel.app`).
  - Permits explicitly configured Chrome Extension IDs matching the standard 32-lowercase-letter format (`/^[a-z]{32}$/`).
  - Permits local development origins (`http://localhost:*`, `http://127.0.0.1:*`).
  - Rejects arbitrary websites, unapproved Vercel projects, and unknown extension IDs with `403 Forbidden`.
- **Public Abuse Protection & Rate Limiting**:
  - Implements an IP-based sliding-window rate limiter (20 requests per minute, burst cap of 5 per 5 seconds) returning `429 Too Many Requests` with `Retry-After` headers.
  - *Architecture Note*: This built-in limiter enforces instance-level protection on serverless compute. For globally synchronized multi-region rate limiting across all edge nodes, an external distributed store (such as Upstash Redis or Vercel KV with `@upstash/ratelimit`) should be configured.
- **Payload Size Limits**: Rejects requests exceeding 16KB (`413 Payload Too Large`) to protect against memory exhaustion.
- **Backend Endpoint Validation**: The Chrome Extension validates backend URLs against an exact allowlist (`aheadguard-ai.vercel.app` on HTTPS and localhost/127.0.0.1), preventing rogue redirection to third-party endpoints.
- **Safe Error Redaction**: Upstream provider errors, API keys, and stack traces are redacted before delivery to the client.

---

## Project Structure

```
aheadguard-mvp-starter/
├── app/
│   ├── api/
│   │   └── investigate/
│   │       └── route.ts          # Server-side investigation API, SSE streaming, CORS & rate limiting
│   ├── globals.css               # Dark cybersecurity guardian design tokens & styles
│   ├── layout.tsx                # Root layout & security metadata
│   └── page.tsx                  # Web dashboard UI, HUD terminal, Action Preview & Ledger
├── extension/
│   ├── manifest.json             # Chrome Manifest V3 declaration (narrow permissions, no content scripts)
│   ├── popup.html                # Extension popup markup
│   ├── popup.css                 # Dark cybersecurity popup styles
│   ├── background.js             # Bundled service worker
│   ├── popup.js                  # Bundled popup script
│   └── src/
│       ├── api-client.ts         # Extension API client with timeout & error handling
│       ├── background.ts         # Service worker, navigation monitor & storage manager
│       ├── config.ts             # Production & development backend configuration
│       ├── popup.ts              # Popup UI controller & renderer
│       └── types.ts              # Extension TypeScript definitions
├── lib/
│   ├── policy.ts                 # Deterministic 4-outcome policy engine & Action Preview
│   ├── tinyfish.ts               # TinyFish remote browser runner & SSE parser
│   ├── types.ts                  # Shared data models & evidence schemas
│   └── url-safety.ts             # SSRF prevention & destination safety validator
├── tests/
│   ├── api-security.test.ts      # CORS, rate limiting, payload size, SSRF & header tests
│   ├── extension.test.ts         # Extension settings, ledger & endpoint validation tests
│   ├── policy-engine.test.ts     # Risk classification & Action Preview tests
│   ├── real-world-integration.test.ts # 26 real-world security scenarios
│   ├── smoke.test.ts             # Live TinyFish smoke test (optional live execution)
│   ├── tinyfish-sse.test.ts      # SSE chunk streaming & event parser tests
│   └── url-safety.test.ts        # URL normalization & SSRF blocklist tests
├── build-extension.mjs           # esbuild bundling script for extension assets
├── eslint.config.mjs             # ESLint configuration
├── next.config.ts                # Next.js configuration
├── package.json                  # Dependencies & npm scripts
├── tsconfig.json                 # TypeScript compiler configuration
└── vitest.config.mts             # Vitest test runner configuration
```

---

## Getting Started

### Prerequisites

- **Node.js**: v20.9.0 or later (v24 LTS recommended)
- **npm**: v10+
- **TinyFish API Key**: Obtain from [agent.tinyfish.ai](https://agent.tinyfish.ai/)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/gokul1599/AheadGuard-Ai.git
   cd AheadGuard-Ai
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env.local
   ```
   Edit `.env.local` with your credentials:
   ```env
   # Server-side TinyFish API Key (never commit to git)
   TINYFISH_API_KEY=your_tinyfish_api_key_here

   # Comma-separated 32-character lowercase Chrome Extension IDs approved for CORS
   ALLOWED_EXTENSION_IDS=abcdefghijklmnopqrstuvwxyzabcdef

   # Neon Serverless Postgres Connection String (for persistence)
   DATABASE_URL=postgresql://user:password@ep-sample-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require

   # Administrator Secret Key for querying stored investigation history (/api/investigate?action=history)
   AHEADGUARD_ADMIN_KEY=your_secure_admin_secret_key_here
   ```

4. Build the Chrome extension assets:
   ```bash
   npm run build:extension
   ```

5. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Installing & Configuring the Chrome Extension

### Obtaining your Chrome Extension ID

1. Build the extension bundle:
   ```bash
   npm run build:extension
   ```
2. Open Google Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** via the toggle in the top-right corner.
4. Click **Load unpacked** and select the `extension` folder inside this repository.
5. In the card for **AheadGuard AI**, copy the 32-character lowercase string shown under **ID** (e.g. `abcdefghijklmnopqrstuvwxyzabcdef`).

### Configuring Extension ID in Vercel (Production)

For the Chrome Extension to access the production API at `https://aheadguard-ai.vercel.app/api/investigate`, you must add your extension ID to the server-side environment variables:

1. Open your Vercel project settings:
   **[https://vercel.com/gokul1599/aheadguard-ai/settings/environment-variables](https://vercel.com/gokul1599/aheadguard-ai/settings/environment-variables)**
2. Add a new variable:
   - **Key**: `ALLOWED_EXTENSION_IDS`
   - **Value**: `your_copied_32_character_extension_id`
   - **Environment**: Select `Production` and `Preview`.
3. Click **Save** and redeploy.

Without this setting, the server will defensively reject extension requests with `403 Forbidden: CORS origin not allowed.`

### Production Environment Variables (Vercel)

For production deployment at `https://aheadguard-ai.vercel.app`, configure these environment variables in your Vercel Project Settings (**Settings -> Environment Variables**):

| Variable Name | Required | Description |
|:---|:---:|:---|
| `TINYFISH_API_KEY` | Yes | API key for TinyFish headless web crawler |
| `ALLOWED_EXTENSION_IDS` | Yes | Comma-separated 32-letter Chrome Extension IDs allowed for CORS |
| `DATABASE_URL` | Recommended | Neon PostgreSQL connection string with `?sslmode=require` |
| `AHEADGUARD_ADMIN_KEY` | Recommended | Secret key for administrative history and record access |

> **Note on Administrator Key Configuration:**
> The canonical environment variable name for administrator authentication is strictly `AHEADGUARD_ADMIN_KEY`. AheadGuard AI intentionally does not implement fallback aliases (such as `ADMIN_API_KEY`) to prevent accidental configuration drift or ambiguity across deployment environments.

### Database Migration & Schema Setup

AheadGuard uses an idempotent schema migration runner to provision the `investigations` table and indexes in Neon PostgreSQL.

- **1. Local Development Execution (loads `.env.local`):**
  ```powershell
  npm run db:migrate
  ```
  *(Executes `node --env-file=.env.local scripts/migrate.mjs` using the local development `.env.local` file).*

- **2. Isolated Test Execution (Windows PowerShell with Dedicated Test Database):**
  Use an explicitly identified non-production test database branch to verify migrations without affecting production data:
  ```powershell
  $secUrl = Read-Host "Enter isolated test DATABASE_URL" -AsSecureString
  $bstr = [System.IntPtr]::Zero
  $plainUrl = $null
  try {
      $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secUrl)
      $plainUrl = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
      $env:DATABASE_URL = $plainUrl
      node scripts/migrate.mjs
      if ($LASTEXITCODE -ne 0) { throw "Migration failed with code $LASTEXITCODE" }
      Write-Host "Migration executed successfully on isolated test database." -ForegroundColor Green
  } catch {
      Write-Error "Migration execution error: $_"
  } finally {
      if ($bstr -ne [System.IntPtr]::Zero) {
          [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
      }
      Remove-Item env:DATABASE_URL -ErrorAction SilentlyContinue
      $plainUrl = $null
      $secUrl = $null
  }
  ```

- **3. Production Execution (Owner-Authorized Release Gate Only):**
  Production migration must be executed exclusively by the repository owner following explicit authorization:
  - **Prerequisite 1 — Credential Rotation:** Rotate the Neon database password in the Neon Console to ensure fresh credentials before production deployment.
  - **Prerequisite 2 — Configuration Synchronization:** Update `DATABASE_URL` and `AHEADGUARD_ADMIN_KEY` in Vercel Production Environment Variables.
  - **Prerequisite 3 — Target Branch Confirmation:** Verify that the target database endpoint strictly corresponds to the primary production branch (`main`), not a preview branch or local development database.
  - **Prerequisite 4 — Recovery Plan:** Create an immediate Neon branch snapshot prior to running the migration. Note that point-in-time recovery (PITR) rewinds database state; any investigations logged between the snapshot time and a potential restore would be omitted.
  - **Execution:** Run `node scripts/migrate.mjs` via an ephemeral secure PowerShell session where credentials are provided interactively via `Read-Host -AsSecureString` and never written to disk or logs.
  - **Post-Verification Phase 1 — Database Readiness Gate:**
    Run the strict readiness smoke gate to verify that the deployed edge environment reports active database connectivity:
    ```powershell
    npm run test:smoke:db
    ```
    *(Verifies `GET /api/investigate` returns `{ db: { status: "connected", ok: true } }` without secret leakage. Note: this validates connectivity and schema contract readiness, not full write/read persistence).*
  - **Post-Verification Phase 2 — Production Persistence Certification Gate:**
    Execute the dedicated, opt-in persistence verification probe to certify true end-to-end database write and authorized read:
    ```powershell
    $env:RUN_LIVE_PERSISTENCE_TEST = "true"
    $env:AHEADGUARD_ADMIN_KEY = "your_production_admin_secret_key"
    npm run test:smoke:persistence -- --confirm-live-persistence --prod
    ```
    *(Submits a harmless text-only probe containing a unique audit marker and NO URLs to avoid TinyFish provider charges. Asserts that the response confirms `report.investigationId`, `report.persisted === true`, and `report.storageMode === "persisted"`. Verifies that an unauthenticated GET is rejected with HTTP 401 Unauthorized, and confirms that an authenticated GET with `Authorization: Bearer <key>` retrieves the exact record).*
  - **Persistence Release Gate Certification Rule:**
    Production persistence is officially certified **only** after Phase 2 succeeds with verified database write and authenticated read confirmation. Verification records contain a distinct marker prefix (`aheadguard-persistence-probe-...`) and remain safely recorded in Neon PostgreSQL; AheadGuard deliberately does not expose an unauthenticated deletion endpoint to safeguard audit ledger immutability.
  - **Persistence Verifier Security & Target Authorization Controls:**
    - **Strict Production Origin:** `--prod` mode permits only the canonical production origin `https://aheadguard-ai.vercel.app`. Any conflicting `--url` is rejected before network dispatch.
    - **Custom Target Allowlisting:** Custom destinations require explicit origin authorization via `--allow-origin=<origin>`. Plain HTTP is prohibited for all non-loopback destinations. Embedded credentials (URL userinfo) are strictly rejected.
    - **Credential Isolation:** Passing credentials via command-line flags (`--key`) is disabled. The administrator key is read exclusively from `AHEADGUARD_ADMIN_KEY` in the process environment.
    - **Redirect & Timeout Boundary:** Verification requests reject unexpected redirects (`redirect: "error"`) to prevent credential leakage. Timeouts strictly cover the complete lifecycle including response body parsing.
    - **Marker Verification:** The verifier asserts that the unique audit marker generated for the write is present in the persisted record returned during the authenticated read.

> **Security Analysis of PowerShell .NET Memory Boundary:**
> `Read-Host -AsSecureString` prevents terminal echo and excludes sensitive input from `PSReadLine` command history (`ConsoleHistory.txt`). `Marshal.ZeroFreeBSTR` immediately zeroes unmanaged BSTR memory. However, passing the credential to Node.js requires conversion to a .NET string (`PtrToStringBSTR`), which allocates an immutable managed `System.String` on the CLR heap that cannot be explicitly zeroized from script execution and persists until garbage collection. In the `finally` block, `Remove-Item env:DATABASE_URL` clears the process environment variable and `$plainUrl = $null` unroots the managed string reference. For zero-residual compliance, execute migrations in an ephemeral PowerShell sub-process (`powershell -NoProfile -Command ...`).

> **Migration Concurrency & Non-Destructive Integrity Safety:**
> 1. **Dedicated Session & Advisory Locking:** The migration establishes a single dedicated PostgreSQL connection (`Client`) over WebSockets (via the `ws` package) rather than stateless HTTP requests. It configures bounded session timeouts (`SET lock_timeout = '5000ms';` and `SET statement_timeout = '10000ms';`) and acquires a session-level advisory lock (`pg_advisory_lock(7429103)`). All pre-validation checks and DDL run on this exact live session. The lock is released on the same session in `finally`, and closing the session (`client.end()`) guarantees PostgreSQL will release any session locks even in the event of an abnormal abort.
> 2. **Pre-Validation on Existing Tables:** If `public.investigations` already exists, the runner pre-validates column specifications, data types, nullability, and primary key constraints **before** attempting any index creation or DDL mutations. If drift is detected, it aborts immediately with 0 mutations.
> 3. **Comprehensive Verification:** Following table/index provisioning, the runner validates all 10 column specifications, primary key on `id`, index definitions (including descending sort on `created_at`), and detects foreign index collisions in schema `public`.
> 4. **No Destructive Operations & Recovery Nuances:** Never execute `DROP TABLE` on production databases. For disaster recovery, utilize Neon point-in-time recovery (PITR) or branch snapshots. Note the operational consequences:
>    - Restoring an earlier snapshot rewinds state and omits valid investigation records written after the snapshot timestamp.
>    - Restoring to a new branch provisions a distinct connection endpoint; application and migration configurations must be deliberately updated to route to the new endpoint.
>    - Existing connections to the prior endpoint will fail or write to stale branches.
>    - Always manually verify table definitions and record integrity immediately after restoration before routing user traffic.

### Client IP Resolution & Rate Limiting Trust Model

AheadGuard implements an in-memory sliding window rate limiter (20 req/min, burst 5 req/5s per IP) on `/api/investigate`.

- **Proxy Trust Boundary & Anti-Spoofing:** On Vercel (`https://aheadguard-ai.vercel.app`), the edge reverse proxy terminates the incoming client TCP connection and unconditionally overwrites `X-Real-IP` with the client socket IP address. AheadGuard strictly resolves client IP from `X-Real-IP`. Client-supplied `X-Real-IP` headers are discarded at the edge.
- **Elimination of Unverified Fallbacks:** Forwarding headers like `X-Forwarded-For` are client-controlled and untrusted. AheadGuard **never** falls back to `X-Forwarded-For` when `X-Real-IP` is absent or malformed. Treating client-provided forwarding headers as authoritative would allow attackers to rotate headers and bypass rate limits entirely.
- **Fallback Policy & Availability Impact:** If `X-Real-IP` is absent, empty, whitespace-only, or syntactically invalid (e.g. malformed IP), the request maps to the fallback loopback bucket (`127.0.0.1`).
  - *Availability limitation:* Unverified requests without a valid canonical IP share this single bucket. An attacker flooding unverified requests can exhaust this fallback bucket, resulting in HTTP 429 responses for other requests lacking a canonical IP.
  - *Isolation guarantee:* Legitimate external clients with valid canonical `X-Real-IP` headers operate in independent rate-limit buckets and are completely unaffected by fallback bucket exhaustion.
- **Upstream Reverse Proxy / CDN Boundary:** If an external CDN or reverse proxy (such as Cloudflare) is layered in front of Vercel without enterprise custom proxy header configuration, Vercel Edge treats the external proxy's egress node as the client IP, grouping proxied requests into the same rate-limit bucket.
- **Syntactic Validation & Dual-Stack Normalization:** All candidate addresses are verified via Node.js `net.isIP()`. IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalized to IPv4 to prevent bucket splitting between IPv4 and dual-stack clients.
- **Architecture Note:** The rate limiter operates per serverless compute container instance. In multi-container or serverless cold-start topologies, rate limits are instance-local. For globally synchronized multi-region rate limiting across all edge nodes, an external distributed store (such as Upstash Redis or Vercel KV with `@upstash/ratelimit`) should be configured.

---

## Running Verification Tests

AheadGuard AI includes a comprehensive suite of automated tests verifying CORS allowlisting, rate limiting, safety policies, SSE streaming, and 26 real-world security scenarios:

```bash
# Run unit & integration test suite (Vitest - 350+ automated tests)
npm test

# Run default smoke test suite (opt-in tests skipped)
npm run test:smoke

# Run live provider smoke test (requires TINYFISH_API_KEY)
npm run test:smoke:live

# Run live production deployment smoke test (tests endpoint reachability & safe fallback contract)
npm run test:smoke:prod

# Run strict production database readiness smoke test (verifies active connectivity via GET /api/investigate)
npm run test:smoke:db

# Run dedicated production persistence certification probe (opt-in end-to-end write & authorized read verification)
npm run test:smoke:persistence -- --confirm-live-persistence --prod

# Run ESLint
npm run lint

# Run TypeScript type check
npx tsc --noEmit

# Run Next.js production build
npm run build

# Run Chrome Extension build
npm run build:extension
```

### Continuous Integration (CI/CD)

The repository includes a GitHub Actions workflow (`.github/workflows/ci.yml`) configured for Node.js 24 on `ubuntu-latest`. It automatically executes on every push and pull request to `main`:
1. Dependency integrity check (`npm ci`)
2. Code style and static analysis (`npm run lint`)
3. Strict TypeScript compilation (`npx tsc --noEmit`)
4. Complete unit and integration test suite (`npm test`)
5. Clean-environment smoke tests (`npm run test:smoke`)
6. Chrome Extension artifact build (`npm run build:extension`)
7. Next.js production build (`npm run build`)

---

## License

This project is licensed under the [MIT License](LICENSE).
