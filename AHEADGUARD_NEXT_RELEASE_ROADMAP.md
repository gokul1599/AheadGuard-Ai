# AHEADGUARD AI — PRODUCTION ROADMAP & OPERATIONAL READINESS PLAN

**Product:** Cross-Platform Digital Trust Intelligence Platform  
**Target Milestone:** Post-3.0 Production Hardening & Ecosystem Activation  
**Live Production Endpoint:** [https://aheadguard-ai.vercel.app/](https://aheadguard-ai.vercel.app/)  
**GitHub Repository:** [https://github.com/gokul1599/AheadGuard-Ai](https://github.com/gokul1599/AheadGuard-Ai)  
**Author:** Production Engineering & Release Architecture Group  

---

## 1. CRITICAL BLOCKERS & IMMEDIATE PRODUCTION PREREQUISITES

AheadGuard AI 2.0 and AheadGuard AI 3.0 core capabilities (Unified Orchestrator, Offer Integrity, TrustGraph, Transaction Truth, Evidence Ledger, and Durable Queue) are **fully operational and live-verified**.

There are **zero blockers** preventing core web investigations, API integrations, Chrome extension usage, or mobile share processing.

The only operational requirements for full third-party bot activation are external developer credentials and API keys:

| Integration | Current Block Status | Required External Action |
| :--- | :--- | :--- |
| **Telegram Bot** | Pending Bot Token | Register bot with `@BotFather`, obtain token, set `TELEGRAM_BOT_TOKEN` in Vercel. |
| **Discord Bot** | Pending App Registration | Create bot in Discord Developer Portal, set `DISCORD_PUBLIC_KEY` & `DISCORD_BOT_TOKEN`. |
| **WhatsApp Business** | Pending Meta Review | Create Meta Developer App, configure WhatsApp Cloud API webhook with verify token. |
| **Instagram DM** | Pending App Verification | Complete Meta Business Verification for Instagram Messaging permission. |
| **Gmail / Email** | Pending Inbound MX Setup | Set up SendGrid Inbound Parse or AWS SES inbound rule pointing to `/api/investigate/webhook/email`. |
| **X (Twitter)** | Pending Developer Access | Request Elevated Access for Account Activity API / Direct Messages. |
| **LinkedIn** | Pending Partner Access | Apply for Community Management / Messaging API access via LinkedIn Developer Portal. |
| **TikTok** | Pending Developer Webhook | Register Webhook URL in TikTok for Developers portal. |

---

## 2. PRODUCTION ENVIRONMENT CONFIGURATION SPECIFICATION

To activate the complete embedded agent ecosystem, provide the following environment variables in the Vercel Production Environment Settings:

```bash
# =================================================================
# 1. CORE DATABASE & INTELLIGENCE RUNTIME (ACTIVE & VERIFIED)
# =================================================================
DATABASE_URL="postgresql://neondb_owner:***@ep-delicate-forest-a1e6z2z3-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"
TINYFISH_API_KEY="sk-tinyfish-***"
NEXT_PUBLIC_APP_URL="https://aheadguard-ai.vercel.app"

# =================================================================
# 2. DURABLE QUEUE & BACKGROUND WORKER AUTHENTICATION
# =================================================================
CRON_SECRET="generate-a-high-entropy-64-character-hex-string"
WORKER_CONCURRENCY_LIMIT="10"
MAX_JOB_RETRIES="3"
JOB_RETENTION_DAYS="30"

# =================================================================
# 3. TELEGRAM INTEGRATION
# =================================================================
TELEGRAM_BOT_TOKEN="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
TELEGRAM_WEBHOOK_SECRET="generate-telegram-webhook-secret-token"
TELEGRAM_BOT_USERNAME="AheadGuardBot"

# =================================================================
# 4. DISCORD INTEGRATION
# =================================================================
DISCORD_APPLICATION_ID="123456789012345678"
DISCORD_PUBLIC_KEY="ed25519-public-key-from-discord-portal"
DISCORD_BOT_TOKEN="discord-bot-token-from-bot-tab"

# =================================================================
# 5. WHATSAPP & INSTAGRAM (META CLOUD API)
# =================================================================
META_APP_ID="1234567890"
META_APP_SECRET="meta-app-secret-32-chars"
WHATSAPP_PHONE_NUMBER_ID="phone-number-id-from-meta"
WHATSAPP_ACCESS_TOKEN="system-user-permanent-token"
WHATSAPP_WEBHOOK_VERIFY_TOKEN="custom-verify-token-for-meta-challenge"
INSTAGRAM_ACCOUNT_ID="instagram-business-account-id"
INSTAGRAM_PAGE_ACCESS_TOKEN="page-access-token-for-instagram"

# =================================================================
# 6. INBOUND EMAIL / GMAIL PARSER
# =================================================================
EMAIL_INBOUND_SECRET="sendgrid-or-ses-webhook-signing-key"
FORWARDING_EMAIL_ADDRESS="check@safety.aheadguard.ai"

# =================================================================
# 7. X (TWITTER) DIRECT MESSAGE BOT
# =================================================================
X_CONSUMER_KEY="x-api-consumer-key"
X_CONSUMER_SECRET="x-api-consumer-secret"
X_ACCESS_TOKEN="x-access-token"
X_ACCESS_TOKEN_SECRET="x-access-token-secret"
X_BEARER_TOKEN="x-bearer-token"

# =================================================================
# 8. SECURITY & RATE LIMITING
# =================================================================
UPSTASH_REDIS_REST_URL="https://***.upstash.io"
UPSTASH_REDIS_REST_TOKEN="***"
INVESTIGATION_RATE_LIMIT_PER_MINUTE="30"
WEBHOOK_RATE_LIMIT_PER_MINUTE="120"
```

---

## 3. SECURITY HARDENING & DEFENSIVE INFRASTRUCTURE

### 3.1 Rate Limiting & Abuse Prevention
- **Implementation Target**: Deploy Upstash Redis rate limiting on all public investigation endpoints (`/api/investigate`, `/api/offer-integrity`, `/api/transaction-truth`, `/api/mobile/share`).
- **Policy**:
  - Unauthenticated Web IP: 20 investigations / hour.
  - Authenticated Users / Mobile Device UUID: 120 investigations / hour.
  - Platform Webhooks: 600 requests / minute (protected by cryptographic signatures).
- **Graceful Response**: Return standard HTTP 429 with `Retry-After` header and user-facing friendly guidance.

### 3.2 Egress IP Pinning & SSRF Mitigation
- **Egress Restriction**: When TinyFish or the Unified Orchestrator performs HTTP scrapes of claimed company portals, use an egress proxy that rejects RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`).
- **Payload Caps**: Enforce a strict 512 KB payload size limit on incoming webhook bodies to protect serverless instances from memory pressure.

### 3.3 WAF & Header Security
- Configure Cloudflare / Vercel Edge WAF rules:
  - Block automated scrapers targeting investigation endpoints without user-agent headers.
  - Enforce `Content-Security-Policy: default-src 'self' ...; frame-ancestors 'none';` across all responses.
  - Maintain `X-Content-Type-Options: nosniff` and `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.

---

## 4. STEP-BY-STEP ACTIVATION WORKFLOWS FOR PLATFORM INTEGRATIONS

### 4.1 Telegram Activation (Immediate, ~5 Minutes)
1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`, name it `AheadGuard AI`, and set username (e.g. `AheadGuardAIBot`).
3. Copy the HTTP API token provided by BotFather.
4. Go to Vercel Project Dashboard -> Settings -> Environment Variables.
5. Add `TELEGRAM_BOT_TOKEN` = `<your-token>` and `TELEGRAM_WEBHOOK_SECRET` = `<random-32-char-string>`.
6. Run the automated webhook registration command:
   ```bash
   curl -X POST "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://aheadguard-ai.vercel.app/api/investigate/webhook/telegram",
       "secret_token": "<TELEGRAM_WEBHOOK_SECRET>",
       "allowed_updates": ["message"]
     }'
   ```
7. Open your new bot in Telegram and send `/start` or forward a suspicious internship offer. AheadGuard will respond immediately with formatted risk analysis.

### 4.2 Discord Bot Activation (~10 Minutes)
1. Navigate to the [Discord Developer Portal](https://discord.com/developers/applications).
2. Click "New Application", name it `AheadGuard AI`.
3. In the "General Information" tab, copy the **Public Key**. Set `DISCORD_PUBLIC_KEY` in Vercel.
4. In the "Interactions Endpoint URL" field, enter:
   `https://aheadguard-ai.vercel.app/api/investigate/webhook/discord`
   Discord will immediately send an Ed25519 PING challenge; AheadGuard's verified adapter will reply with PONG.
5. In the "Bot" tab, click "Reset Token" and copy the bot token. Set `DISCORD_BOT_TOKEN` in Vercel.
6. Register the slash commands (`/check`, `/offer`, `/payment`) using Discord's REST API.

### 4.3 WhatsApp Business Cloud API Activation (~30 Minutes)
1. Go to [Meta for Developers](https://developers.facebook.com/) and create a Business App.
2. Add the **WhatsApp** product.
3. Under WhatsApp -> Configuration:
   - Callback URL: `https://aheadguard-ai.vercel.app/api/investigate/webhook/whatsapp`
   - Verify Token: Enter your configured `WHATSAPP_WEBHOOK_VERIFY_TOKEN`.
4. Click "Verify and Save". Meta will send a GET challenge request; AheadGuard will validate the token and return the `hub.challenge` string.
5. Subscribe to the `messages` webhook field.
6. Configure the System User with permanent WhatsApp Cloud API messaging permissions.

### 4.4 Mobile App Store Publishing (Android & iOS)
- **Android APK / Google Play**:
  - The Android intent handler is fully operational at `/api/mobile/share`.
  - Compile the React Native / Kotlin wrapper in `android/` with package ID `ai.aheadguard.app`.
  - Register the `android.intent.action.SEND` filter in `AndroidManifest.xml` targeting MIME types `text/plain` and `text/html`.
  - Sign the release AAB bundle and upload to Google Play Console Internal Testing track.
- **iOS App Store / TestFlight**:
  - Build the Swift Action Extension in Xcode targeting iOS 16+.
  - Register `NSExtensionActivationRule` accepting `kUTTypePlainText` and `kUTTypeURL`.
  - Post shared content to `https://aheadguard-ai.vercel.app/api/mobile/share`.
  - Upload build to App Store Connect TestFlight.

---

## 5. RELIABILITY, RESILIENCE & SCALING

### 5.1 Worker Concurrency & Vercel Cron Scheduling
- In serverless environments, background execution is triggered via Vercel Cron (`cron.json`):
  ```json
  {
    "crons": [
      {
        "path": "/api/jobs/worker",
        "schedule": "* * * * *"
      }
    ]
  }
  ```
- **PostgreSQL Advisory Locking**: The worker uses `FOR UPDATE SKIP LOCKED` to enable multiple concurrent serverless worker invocations without race conditions or duplicate execution.
- **Backoff & Jitter**: Jobs entering `RETRY_WAIT` follow exponential backoff (`Math.min(baseInterval * 2 ** attempts, 3600000)`) with randomized jitter to prevent thundering herd problems on upstream endpoints.

### 5.2 Dead Letter Queue Alerting & Sentry Integration
- Jobs that fail 3 consecutive attempts transition to `DEAD_LETTER`.
- Hook `DEAD_LETTER` events into Sentry / PagerDuty via an automated webhook to alert reliability engineers.
- Build an administrative replay CLI script: `scripts/replay-dead-letter-jobs.mjs`.

### 5.3 Database Connection Health & Read Replicas
- The Neon Serverless pooler (`ep-delicate-forest-a1e6z2z3-pooler`) manages up to 10,000 idle and active client connections.
- For high-volume read queries (e.g. public TrustGraph lookups and recent community warnings), route queries to Neon read replicas using `DATABASE_READ_URL`.

---

## 6. UX & PRODUCT ENHANCEMENTS (V3.1 & BEYOND)

### 6.1 Real-Time Streaming for Mobile Share Sheet
- Enable SSE (Server-Sent Events) on `/api/mobile/share` so the mobile share sheet can render a progressive progress bar:
  1. *Extracting entities... (15%)*
  2. *Scanning company recruiting policies... (45%)*
  3. *Verifying bank handle and payment request... (80%)*
  4. *Final Verdict & Safe Action Plan Ready (100%)*

### 6.2 Rich Messaging Embeds & Visual Risk Cards
- Generate dynamic OpenGraph summary cards (PNG images rendered via `@vercel/og`) for investigations shared on Telegram, Discord, and WhatsApp.
- Users see a clear visual safety card with red/yellow/green color grading and the official tagline:
  > *"AheadGuard AI: Your AI checks first. You act with confidence."*

---

## 7. STRATEGIC FUTURE CAPABILITIES (AHEADGUARD 4.0 ROADMAP)

1. **Voice Call Scam Intelligence**: Real-time audio stream monitoring for Android (via Accessibility Services or call recording where legally permitted) detecting typical urgency phrases ("immediate police arrest", "electricity disconnection", "customs parcel held").
2. **Biometric & Face Swap Deepfake Detection**: High-speed video frame analysis detecting AI-generated recruitment video interviews or synthetic identity impersonation.
3. **Enterprise Digital Safety API**: Multi-tenant B2B API allowing university placement offices, job boards (Indeed, Naukri, LinkedIn), and freelance platforms (Upwork, Fiverr) to screen job postings before they go live.
4. **Decentralized Reputation Network**: Cryptographically signed evidence hashes published to an immutable public trust log, ensuring tamper-proof scam records across independent security researchers.
