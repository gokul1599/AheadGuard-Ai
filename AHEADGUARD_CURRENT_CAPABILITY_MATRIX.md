# AHEADGUARD AI — CURRENT PLATFORM CAPABILITY & INTEGRATION MATRIX

**Product:** AheadGuard AI — The Cross-Platform Digital Trust Intelligence Platform  
**Team:** CODESTROME  
**Program:** Swim with TinyFish × Scaler School of Technology  
**Audit Date:** 2026-11-01  
**Audit Standard:** Capability Honesty — Never treat an adapter or UI control as a verified live integration.  

---

## 1. STATUS TAXONOMY DEFINITION

* **NOT_IMPLEMENTED:** Feature is not in the codebase.
* **IMPLEMENTED:** Code exists, functions, and compiles, but lacks live credentials or environmental setup.
* **CONFIGURED:** Environment variables, schemas, and configurations exist and have been validated.
* **CONNECTED:** Active communication verified with upstream provider APIs.
* **TESTED:** Comprehensive automated unit, integration, and regression tests pass.
* **PRODUCTION VERIFIED:** Deployed to Vercel production and validated on live endpoints.
* **PLANNED:** On the product roadmap, not yet implemented.
* **BLOCKED:** Dependent on third-party API approval or enterprise credential access.

---

## 2. INTELLIGENCE & VERIFICATION MODULES

| Module / Capability | Status | Evidence & Verification Details |
| :--- | :--- | :--- |
| **Structured Claim Extraction** | **PRODUCTION VERIFIED** | Extracts claimed employer, role, duration, recruiter name, channel, payment, upiId, stipend, and selection process across 12 categories (`lib/offer-integrity/claim-extractor.ts`). |
| **Vacancy Requisition Verification** | **PRODUCTION VERIFIED** | Replaces substring matching with strict domain security, ATS tenant validation, requisition ID parsing (`extractRequisitionId`), and live listing inspection (`lib/offer-integrity/vacancy-verifier.ts`). |
| **Recruiter Identity Decomposition** | **PRODUCTION VERIFIED** | Separates Claimed Identity (`OBSERVED`), Email-Domain Consistency (`MATCHED_DOMAIN`), Individual Identity (`UNVERIFIED`), and Employer Affiliation (`SUPPORTED`). Prevents false verification badges. |
| **Live Corporate Policy Verification** | **PRODUCTION VERIFIED** | Separates cached catalog references (`CACHED_CATALOG`) from live crawl results (`LIVE_RETRIEVAL`). Explicitly reports `CHECK_FAILED` on provider failure. |
| **Upfront Fee & Payment Detection** | **PRODUCTION VERIFIED** | Evaluates behavioral fee requests regardless of whether numeric amounts are disclosed. Never outputs "Zero Fees Requested" for mandatory fees (`lib/recruitment-intelligence.ts`). |
| **Deterministic 4-Tier Risk Engine** | **PRODUCTION VERIFIED** | Enforces `HIGH RISK`, `SUSPICIOUS`, `UNKNOWN`, and `LOW OBSERVED RISK` deterministically based on verified evidence and policy contradictions. |
| **TinyFish Live Web Research** | **CONNECTED & TESTED** | SSE client stream handles `STARTED`, `PROGRESS`, `STREAMING_URL`, `HEARTBEAT`, and `COMPLETE`. Connected to Offer Integrity with read-only sandbox safety (`lib/tinyfish.ts`). |
| **TrustGraph Entity Resolution** | **PRODUCTION VERIFIED** | Ingests entities (`PHONE`, `EMAIL`, `DOMAIN`, `UPI_VPA`, `ORG_ENTITY`), computes SHA-256 node IDs, and stitches cross-channel campaign relationships (`lib/trustgraph/`). |
| **Transaction Truth Verification** | **PRODUCTION VERIFIED** | Detects fraudulent transaction requests, payment traps, and lookalike receiver accounts (`lib/transaction-truth/`). |
| **Adversarial Prompt Injection Defense**| **PRODUCTION VERIFIED** | Strips injection attempts in crawled content; strictly prevents retrieved web text from overriding deterministic safety policies. |

---

## 3. PLATFORM INTEGRATIONS & INGESTION CHANNELS

| Channel / Integration | Status | Actual Implementation Details & Limitations |
| :--- | :--- | :--- |
| **Web Application (Desktop & Mobile)** | **PRODUCTION VERIFIED** | Next.js 15 app router, responsive Tailwind/CSS UI, client investigation forms, and live SSE progress streaming (`app/page.tsx`). |
| **Offer Integrity REST API** | **PRODUCTION VERIFIED** | Endpoints `/api/offer-integrity` (GET, POST, OPTIONS) with strict origin allowlist, rate limiting, and CORS preflight handling. |
| **General Investigation API** | **PRODUCTION VERIFIED** | Endpoint `/api/investigate` executing live TinyFish browser investigations with streaming progress and fallback recovery. |
| **Chrome Extension (Manifest V3)** | **TESTED** | Extension codebase (`extension/`) with background service worker, side panel, context menu, and omnibox integration. Verified in Vitest; pending Web Store publication. |
| **Telegram Ingest Webhook** | **CONNECTED & TESTED** | Webhook handler at `/api/investigate/webhook/telegram` with secret token validation, update deduplication, and message investigation response formatting. |
| **WhatsApp Business Integration** | **CONFIGURED & TESTED** | Webhook adapter at `/api/investigate/webhook/whatsapp` verifying `hub.verify_token` and Meta signature. Live messaging requires production Cloud API token. |
| **Instagram Professional Integration** | **CONFIGURED & TESTED** | Webhook adapter at `/api/investigate/webhook/instagram` verifying Meta challenge tokens. Requires approved Meta App credentials for live DM processing. |
| **Discord Bot Integration** | **IMPLEMENTED & TESTED** | Ed25519 signature verification and interaction handler at `/api/investigate/webhook/discord`. Verified with mock interaction payloads. |
| **iOS WebKit / Safari Compatibility** | **PRODUCTION VERIFIED** | Origin normalization, CORS headers without wildcard reflection, preflight cache control, and mobile viewport optimization. |
| **Android & iOS Share Target** | **PRODUCTION VERIFIED** | Native Web Share API target handler at `/api/mobile/share` processing incoming text/links without credential leaks. |
| **Gmail OAuth Direct Ingest** | **PLANNED** | Roadmap integration for workspace security; awaiting Google Cloud OAuth verification for restricted email scopes. |
| **LinkedIn Ingest Adapter** | **PLANNED** | Dependent on authorized LinkedIn Developer Application partnership. |
| **X / Twitter Ingest Webhook** | **PLANNED** | Roadmap integration for social trust checks. |

---

## 4. DATABASE & INFRASTRUCTURE CAPABILITIES

| Infrastructure Layer | Status | Deployment & Resilience Characteristics |
| :--- | :--- | :--- |
| **Neon Serverless PostgreSQL** | **CONNECTED & TESTED** | Relational storage for investigation reports, trust graph entities, and durable job queues with connection pooling (`lib/db.ts`). |
| **Ephemeral Memory Fallback** | **PRODUCTION VERIFIED** | Non-blocking fallback to in-memory store if database connection pool is exhausted or during cold migration phases. |
| **Durable Execution Engine** | **TESTED** | Headless queue worker (`lib/jobs/`) with exponential backoff retries, heartbeat checks, and duplicate task deduplication. |
| **Vercel Edge & Serverless Hosting**| **PRODUCTION VERIFIED** | Global edge CDN, route caching, and automated HTTPS enforcement on `aheadguard-ai.vercel.app`. |
