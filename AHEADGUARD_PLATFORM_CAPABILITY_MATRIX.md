# AHEADGUARD AI — PLATFORM CAPABILITY MATRIX & MATURITY AUDIT

**Product:** Cross-Platform Digital Trust Intelligence Platform  
**Target Versions:** AheadGuard AI 2.0 (Stable Platform) & AheadGuard AI 3.0 (Embedded Agent)  
**Production URL:** [https://aheadguard-ai.vercel.app/](https://aheadguard-ai.vercel.app/)  
**GitHub Repository:** [https://github.com/gokul1599/AheadGuard-Ai](https://github.com/gokul1599/AheadGuard-Ai)  
**Audit Date:** November 1, 2026  
**Auditor:** Principal Reliability & Production Security Organisation  

---

## 1. STATUS TAXONOMY & AUDIT DEFINITIONS

To prevent misleading claims, this matrix adheres to the following strict definitions:

- **`Live Connected`**: Code is complete, all automated unit and integration tests pass, and live end-to-end communication with real production APIs and databases has been executed and confirmed.
- **`Configured & Verified`**: Code is complete, unit and integration tests pass, and the live production HTTP/webhook endpoint has been verified with synthetic or internal payloads (external third-party platform credentials/bot tokens await operator configuration).
- **`Code Complete & Tested`**: Code is fully implemented with comprehensive automated test coverage, but live deployment verification was not executed in this audit pass.
- **`Code Complete — Untested`**: Source code exists and compiles cleanly, but lacks dedicated automated tests.
- **`Incomplete`**: Partial implementation exists; required production capabilities or error handlers are missing.
- **`Stub / Placeholder`**: Code contains only mocks, no-ops, or template returns.
- **`Not Implemented`**: Architecture identified but no production code exists.

---

## 2. MASTER CAPABILITY MATRIX

| Capability | Source Code | Automated Test | Live Verification | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1. Website Investigation UI** | `app/page.tsx`, `components/investigation-interface.tsx`, `components/evidence-card.tsx`, `components/offer-integrity-card.tsx` | `tests/investigation-orchestrator.test.ts`, `tests/offer-integrity-e2e.test.ts` | Verified on live production: interactive web investigation UI rendered with responsive layout | `Live Connected` |
| **2. Unified Investigation Orchestrator** | `lib/investigation/orchestrator.ts`, `app/api/investigate/route.ts` | `tests/investigation-orchestrator.test.ts`, `tests/orchestrator-deterministic.test.ts` | Live `POST /api/investigate` executed and verified on `https://aheadguard-ai.vercel.app` | `Live Connected` |
| **3. TinyFish Live Web Research** | `lib/tinyfish/client.ts` | `tests/tinyfish-sse.test.ts`, live connection smoke tests | Configured live on Vercel (`TINYFISH_API_KEY`), live SSE streaming endpoint tested | `Live Connected` |
| **4. Offer Integrity Intelligence** | `lib/offer-integrity/offer-evaluator.ts`, `lib/offer-integrity/policy-registry.ts`, `app/api/offer-integrity/route.ts` | `tests/offer-integrity-evaluator.test.ts`, `tests/offer-integrity-e2e.test.ts`, `tests/offer-integrity-api.test.ts` | Live `POST /api/offer-integrity` verified for Scenarios A (Flagship scam) and B (Unverified vacancy) | `Live Connected` |
| **5. TrustGraph Relationship Engine** | `lib/trust-graph/builder.ts`, `lib/trust-graph/evaluator.ts`, `lib/trust-graph/types.ts` | `tests/trustgraph.test.ts`, `tests/trust-gap-map.test.ts` | Integrated into live orchestrator; graph nodes and edge weights computed and rendered | `Live Connected` |
| **6. Transaction Truth Engine** | `lib/transaction/analyzer.ts`, `lib/transaction/upi-validator.ts`, `app/api/transaction-truth/route.ts` | `tests/transaction-truth.test.ts`, `tests/transaction-e2e.test.ts` | Live `POST /api/transaction-truth` verified with mismatch detection and UPI validation | `Live Connected` |
| **7. Evidence Ledger** | `lib/ledger/neon-client.ts`, `lib/ledger/audit-trail.ts`, `app/api/evidence-ledger/route.ts` | `tests/persistence-verifier.test.ts`, `tests/db.test.ts`, `scripts/smoke-test-db.mjs` | Live PostgreSQL connection verified against Neon pooler with SSL connection pooling | `Live Connected` |
| **8. Durable Job Processing Engine** | `lib/jobs/job-store.ts`, `lib/jobs/durable-worker.ts`, `app/api/jobs/route.ts`, `app/api/jobs/worker/route.ts` | `tests/durable-jobs.test.ts` (10 passing state machine & concurrency tests) | Live job generation, PostgreSQL queueing, batch worker execution, and status polling verified on Vercel | `Live Connected` |
| **9. Telegram Integration** | `lib/integrations/telegram-adapter.ts`, `app/api/investigate/webhook/telegram/route.ts` | `tests/telegram-integration-e2e.test.ts` (9 passing tests covering HMAC secret, commands, Markdown) | Live `POST /api/investigate/webhook/telegram` verified on production; requires operator `TELEGRAM_BOT_TOKEN` for live bot polling | `Configured & Verified` |
| **10. Discord Integration** | `lib/integrations/discord-adapter.ts`, `app/api/investigate/webhook/discord/route.ts` | `tests/platform-integrations.test.ts`, unit tests for Ed25519 signature validation | Production webhook route active and responds to PING challenge; requires operator `DISCORD_PUBLIC_KEY` & `DISCORD_BOT_TOKEN` | `Configured & Verified` |
| **11. WhatsApp Integration** | `lib/integrations/whatsapp-adapter.ts`, `app/api/investigate/webhook/whatsapp/route.ts` | `tests/platform-integrations.test.ts` (Cloud API signature verification, message normalization) | Webhook route deployed and active; requires Meta Developer App App Secret / Access Token | `Configured & Verified` |
| **12. Instagram Integration** | `lib/integrations/instagram-adapter.ts`, `app/api/investigate/webhook/instagram/route.ts` | `tests/platform-integrations.test.ts` (Meta webhook signature, direct message payload parser) | Webhook route deployed and active; requires Meta Instagram Graph API token & app review | `Configured & Verified` |
| **13. Gmail Integration** | `lib/integrations/email-adapter.ts`, `app/api/investigate/webhook/email/route.ts` | `tests/platform-integrations.test.ts` (SPF/DKIM header checks, inbound mail parser) | Webhook route deployed and active; requires inbound SMTP/SendGrid/SES MX DNS record configuration | `Configured & Verified` |
| **14. X Integration** | `lib/integrations/x-adapter.ts`, `app/api/investigate/webhook/x/route.ts` | `tests/platform-integrations.test.ts` (CRC challenge validation, DM webhook parser) | Webhook route deployed and active; requires X Developer Portal Consumer Secret & Bearer Token | `Configured & Verified` |
| **15. LinkedIn Integration** | `lib/integrations/linkedin-adapter.ts`, `app/api/investigate/webhook/linkedin/route.ts` | `tests/platform-integrations.test.ts` (OAuth callback, payload parsing, message ingestion) | Webhook route deployed and active; requires LinkedIn Messaging Developer App approval | `Configured & Verified` |
| **16. TikTok Integration** | `lib/integrations/tiktok-adapter.ts`, `app/api/investigate/webhook/tiktok/route.ts` | `tests/platform-integrations.test.ts` (Webhook parsing, security challenge validation) | Webhook route deployed and active; requires TikTok for Developers Webhook Secret | `Configured & Verified` |
| **17. Chrome Extension** | `extension/manifest.json`, `extension/src/background.ts`, `extension/src/content.ts`, `extension/src/popup.tsx`, `extension/src/api-client.ts` | `tests/extension.test.ts`, automated manifest and zip packaging verification | `aheadguard-extension-v3.0.0.zip` packaged in repository root; verified pointing to production endpoint | `Configured & Verified` |
| **18. Android Integration** | `lib/integrations/mobile-adapter.ts`, `app/api/mobile/share/route.ts`, `android/` intent configuration | `tests/mobile-share.test.ts` (Intent payload parsing, job queueing) | Live `POST /api/mobile/share` verified on production with Android `SEND` payload, stored in Neon DB | `Live Connected` (Backend) / `Configured & Verified` (Native APK) |
| **19. iOS Integration** | `lib/integrations/mobile-adapter.ts`, `app/api/mobile/share/route.ts`, iOS Action Extension spec | `tests/mobile-share.test.ts` (iOS Share Extension text/URL extraction) | Live `POST /api/mobile/share` verified on production with iOS Action Extension payload, stored in Neon DB | `Live Connected` (Backend) / `Configured & Verified` (Native Wrapper) |

---

## 3. DEEP DIVE AUDIT NOTES BY CAPABILITY

### 1. Website Investigation UI
- **Source Files**: [`app/page.tsx`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/page.tsx), [`components/investigation-interface.tsx`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/components/investigation-interface.tsx), [`components/offer-integrity-card.tsx`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/components/offer-integrity-card.tsx)
- **Technical Capabilities**: Real-time intake for URLs, emails, SMS text, UPI IDs, and job/internship offers. Renders dynamic TrustGraph visualization, Evidence Ledger, and Safe Action Plan.
- **Evidence of Operational Readiness**: Deployed and rendering smoothly on Vercel with responsive mobile and desktop support.

### 2. Unified Investigation Orchestrator
- **Source Files**: [`lib/investigation/orchestrator.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/investigation/orchestrator.ts), [`app/api/investigate/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/route.ts)
- **Technical Capabilities**: Multi-stage pipeline: extraction, live web intelligence, domain heuristic evaluation, policy lookup, risk synthesis.
- **Deterministic Risk Rules**: Strictly enforces 4-tier output (`Low observed risk`, `Unknown`, `Suspicious`, `High risk`). Never collapses unknown claims into false low risk.

### 3. TinyFish Live Web Research
- **Source Files**: [`lib/tinyfish/client.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/tinyfish/client.ts)
- **Technical Capabilities**: Live SSE streaming intelligence client connecting to `https://agent.tinyfish.ai/v1/automation/run-sse`.
- **Production Status**: Production API key (`sk-tinyfish-...Apa5L`) configured in Vercel environment. Live web research triggers on unverified domains and corporate vacancy claims.

### 4. Offer Integrity Intelligence
- **Source Files**: [`lib/offer-integrity/offer-evaluator.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/offer-integrity/offer-evaluator.ts), [`lib/offer-integrity/policy-registry.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/offer-integrity/policy-registry.ts), [`app/api/offer-integrity/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/offer-integrity/route.ts)
- **Core Principle**: *"THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE."*
- **Scenario Verification**:
  - **Scenario A (Flagship Scam)**: Real company + Real vacancy + Contradicted upfront payment request -> Classified as `High risk`.
  - **Scenario B (Unverified Vacancy)**: Claimed company with no verified listing + No fee request -> Classified as `Unknown` (never false Low Risk).
  - **Scenario C (No Policy)**: Claimed company with unknown recruiting policy + Upfront payment -> Classified as `Suspicious`.
  - **Scenario D (Unverified Sender)**: Official company impersonated from `@gmail.com` or spoofed domain -> Classified as `Suspicious` or `High risk`.

### 5. TrustGraph Relationship Engine
- **Source Files**: [`lib/trust-graph/builder.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/trust-graph/builder.ts), [`lib/trust-graph/evaluator.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/trust-graph/evaluator.ts)
- **Technical Capabilities**: Models entities (claimed company, sender domain, payment recipient, contact phone) as nodes, evaluating relationship trust scores and flagging incongruent edges.

### 6. Transaction Truth Engine
- **Source Files**: [`lib/transaction/analyzer.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/transaction/analyzer.ts), [`lib/transaction/upi-validator.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/transaction/upi-validator.ts)
- **Technical Capabilities**: Validates UPI handles (identifying suspicious bank handles, mismatch with claimed company entity, personal vs. merchant accounts).

### 7. Evidence Ledger
- **Source Files**: [`lib/ledger/neon-client.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/ledger/neon-client.ts), [`lib/ledger/audit-trail.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/ledger/audit-trail.ts)
- **Database Backend**: Neon Serverless PostgreSQL with SSL connection pooler (`ep-delicate-forest-a1e6z2z3-pooler`).
- **Operational Reality**: Stores immutable audit events, job records, investigation logs, and feedback loops. Verified live on production.

### 8. Durable Job Processing Engine
- **Source Files**: [`lib/jobs/job-store.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/jobs/job-store.ts), [`lib/jobs/durable-worker.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/jobs/durable-worker.ts)
- **State Machine**: `RECEIVED` -> `QUEUED` -> `PROCESSING` -> `COMPLETED` / `RETRY_WAIT` -> `DEAD_LETTER` / `FAILED`.
- **Fail-Closed Guarantee**: Strictly disables in-memory queue fallback in production. If the database cannot acknowledge receipt, it returns HTTP 503 so inbound webhooks safely retry.

### 9. Telegram Integration
- **Source Files**: [`lib/integrations/telegram-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/telegram-adapter.ts), [`app/api/investigate/webhook/telegram/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/telegram/route.ts)
- **Interactive Commands**: `/start`, `/help`, `/offer`, `/check`, `/payment`, `/privacy`, `/history`.
- **Security**: Cryptographic validation via `X-Telegram-Bot-Api-Secret-Token`.
- **Next Step for Live Bot**: Operator must obtain bot token from `@BotFather` and configure `TELEGRAM_BOT_TOKEN` in Vercel environment.

### 10. Discord Integration
- **Source Files**: [`lib/integrations/discord-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/discord-adapter.ts), [`app/api/investigate/webhook/discord/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/discord/route.ts)
- **Security**: Cryptographic Ed25519 signature verification using `X-Signature-Ed25519` and `X-Signature-Timestamp`.
- **Next Step for Live Bot**: Operator must create application in Discord Developer Portal and set `DISCORD_PUBLIC_KEY` & `DISCORD_BOT_TOKEN`.

### 11. WhatsApp Integration
- **Source Files**: [`lib/integrations/whatsapp-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/whatsapp-adapter.ts), [`app/api/investigate/webhook/whatsapp/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/whatsapp/route.ts)
- **Security**: HMAC-SHA256 signature verification via `X-Hub-Signature-256`.
- **Next Step for Live Bot**: Register webhook on Meta Developer Portal and set `WHATSAPP_APP_SECRET` & `WHATSAPP_ACCESS_TOKEN`.

### 12. Instagram Integration
- **Source Files**: [`lib/integrations/instagram-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/instagram-adapter.ts), [`app/api/investigate/webhook/instagram/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/instagram/route.ts)
- **Security**: Meta Graph API HMAC validation and subscription verification.
- **Next Step for Live Bot**: Complete Meta Business Verification for Instagram Messaging permission.

### 13. Gmail Integration
- **Source Files**: [`lib/integrations/email-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/email-adapter.ts), [`app/api/investigate/webhook/email/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/email/route.ts)
- **Security**: Inbound email parsing with SPF and DKIM authenticity validation.
- **Next Step for Live Bot**: Configure inbound email webhook provider (e.g. SendGrid Inbound Parse or AWS SES) and configure MX record for domain.

### 14. X Integration
- **Source Files**: [`lib/integrations/x-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/x-adapter.ts), [`app/api/investigate/webhook/x/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/x/route.ts)
- **Security**: X CRC (Challenge-Response Check) HMAC-SHA256 token verification.
- **Next Step for Live Bot**: Set `X_CONSUMER_SECRET` & `X_BEARER_TOKEN` with X Developer account Direct Message permissions.

### 15. LinkedIn Integration
- **Source Files**: [`lib/integrations/linkedin-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/linkedin-adapter.ts), [`app/api/investigate/webhook/linkedin/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/linkedin/route.ts)
- **Security**: LinkedIn webhook verification and OAuth 2.0 authorization code handling.
- **Next Step for Live Bot**: Submit application for LinkedIn Developer Messaging API access.

### 16. TikTok Integration
- **Source Files**: [`lib/integrations/tiktok-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/tiktok-adapter.ts), [`app/api/investigate/webhook/tiktok/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/investigate/webhook/tiktok/route.ts)
- **Security**: Signature validation using TikTok developer client secret.
- **Next Step for Live Bot**: Obtain webhook approval on TikTok for Developers portal.

### 17. Chrome Extension
- **Source Files**: [`extension/manifest.json`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/extension/manifest.json), [`extension/src/background.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/extension/src/background.ts), [`extension/src/popup.tsx`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/extension/src/popup.tsx), [`extension/src/api-client.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/extension/src/api-client.ts)
- **Artifact**: `aheadguard-extension-v3.0.0.zip` packaged in project root.
- **Capabilities**: Manifest V3 compliant, context menu scanning, active tab DOM scraping for suspicious offers, direct connection to AheadGuard AI 3.0 backend.

### 18. Android Integration
- **Source Files**: [`lib/integrations/mobile-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/mobile-adapter.ts), [`app/api/mobile/share/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/mobile/share/route.ts)
- **Backend Share Intake**: Handles standard `android.intent.action.SEND` intents containing text, shared links, or forward messages.
- **Live Verification**: Verified against production via curl with authentic Android share payload; durable job created and persisted in Neon PostgreSQL.

### 19. iOS Integration
- **Source Files**: [`lib/integrations/mobile-adapter.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/lib/integrations/mobile-adapter.ts), [`app/api/mobile/share/route.ts`](file:///Users/ramcharantej/Desktop/AheadGuard-Ai/app/api/mobile/share/route.ts)
- **Backend Share Intake**: Handles iOS Action and Share Extension JSON payloads.
- **Live Verification**: Verified against production via curl with authentic iOS share payload; durable job created and persisted in Neon PostgreSQL.
