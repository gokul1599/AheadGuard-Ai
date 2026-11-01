# AHEADGUARD AI — EVIDENCE-VERIFIED SYSTEM ARCHITECTURE SPECIFICATION

**Product:** AheadGuard AI — The Cross-Platform Digital Trust Intelligence Platform  
**Team:** CODESTROME  
**Program:** Swim with TinyFish × Scaler School of Technology  
**Version:** Production Release 2.1 & 3.0 (Evidence-Verified Upgrade)  
**Document ID:** `AGY-ARCH-EVIDENCE-VERIFIED-2026`  

---

## 1. END-TO-END CENTRAL INVESTIGATION ARCHITECTURE

AheadGuard AI follows an evidence-first, zero-trust verification pipeline. Every evaluation flows linearly through twelve strictly scoped stages to prevent priority inversions, prompt injection, and false reassurance:

```
USER SUBMISSION (Message / URL / Form Fields)
       │
       ▼
INPUT NORMALIZATION & SECURITY PREFLIGHT
  ├─ URL Syntax & Protocol Validation (HTTP/HTTPS only)
  ├─ SSRF / Private IP / Localhost / RFC 2606 Filtering
  ├─ Embedded Username/Password Defense
  └─ Sensitive OAuth/Token/Secret Stripping
       │
       ▼
STRUCTURED CLAIM EXTRACTION (Deterministic Regex & Heuristic Engine)
  ├─ Employer & Brand Identification
  ├─ Job Requisition & Role Extraction
  ├─ Recruiter Identity & Communication Channel Extraction
  ├─ Payment Request, Amount, Method & UPI Extraction
  ├─ Selection Anomalies (No-Interview, Paywalled Documents)
  └─ Canonical Offer Extraction Baseline Assembly
       │
       ▼
INVESTIGATION ORCHESTRATOR
  ├─ Registry Corroboration (Enterprise Domain Registry, Brand Aliases)
  ├─ External Research Dispatching (TinyFish Live Crawler)
  └─ Failure Simulation & Graceful Degradation Handling
       │
       ▼
TINYFISH LIVE-WEB RESEARCH (Read-Only Isolated Browser Automation)
  ├─ Authenticated SSE Streaming (`/v1/automation/run-sse`)
  ├─ Anti-Prompt Injection & Safe Execution Sandbox
  ├─ Requisition Existence & Title Discovery
  └─ Official Corporate Anti-Recruitment-Fraud Policy Lookup
       │
       ▼
SOURCE EXTRACTION & VALIDATION
  ├─ Hostname Matching (`isApprovedEmployerHost`)
  ├─ ATS Tenant Validation (`verifyAtsEmployerAlignment`)
  └─ Requisition ID Parsing (`extractRequisitionId`)
       │
       ▼
CLAIM-BY-CLAIM INDEPENDENT VERIFICATION
  ├─ Vacancy Verification (`verifyVacancyRequisition`)
  ├─ Policy Verification (`verifyRecruitmentPolicy`)
  ├─ Recruiter Dimensions Decomposition
  └─ Application Destination Security Audit
       │
       ▼
EVIDENCE LEDGER (Trust Gap Map)
  ├─ Status Classification: VERIFIED, OBSERVED, CONTRADICTED, UNVERIFIED
  ├─ Execution Status: SUCCESS, CHECK_FAILED, NOT_CHECKED
  └─ Complete Source Provenance & Retrieval Timestamps
       │
       ▼
DETERMINISTIC 4-TIER RISK ENGINE
  ├─ Core Rule: "THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE"
  ├─ Decoupled Threat Likelihood & Consequence Impact
  └─ Verdict Categories: HIGH RISK, SUSPICIOUS, UNKNOWN, LOW OBSERVED RISK
       │
       ▼
SAFE ACTION PLANNER
  ├─ Immediate Action Directives ("DO NOT PAY THE ₹999 FEE")
  ├─ Verification Checklists & Prohibited User Behaviors
  └─ Verified Official Application Routing
       │
       ▼
PERSISTENCE & GRAPH INTELLIGENCE
  ├─ Neon Serverless PostgreSQL Durable Storage
  ├─ In-Memory / Ephemeral Fallback on Pool Exhaustion
  └─ TrustGraph Entity & Cross-Channel Campaign Stitching
       │
       ▼
FINAL DIGITAL TRUST REPORT (Client UI / Webhook / Chrome Extension)
```

---

## 2. VACANCY VERIFICATION SERVICE PIPELINE

Implemented in `lib/offer-integrity/vacancy-verifier.ts`, this dedicated service replaces unsafe domain substring heuristics with rigorous requisition inspection:

### Domain Security Model
* **Approved Hostname Verification:** Validates that candidate destination hosts either strictly match registered employer domains or represent authorized subdomains (`hostname === target || hostname.endsWith("." + target)`).
* **Anti-Lookalike Enforcement:** Rejects subdomain-confusion attacks such as `amazon.jobs.attacker.example` by computing domain boundaries against registrable domain roots.
* **Applicant Tracking System (ATS) Verification:** For third-party platforms (Greenhouse, Lever, Workday, SmartRecruiters, Ashby, Taleo, iCIMS), the engine extracts the organizational tenant slug from the pathname or subdomain and compares it against known employer aliases. An unauthenticated ATS account belonging to a third party cannot verify a vacancy.

### Requisition Extraction & State Machine
1. Extracts Requisition IDs (`/jobs/10541345/`, `?job_id=10541345`, `?requisitionId=...`).
2. Extracts listing title slugs for natural language role alignment.
3. Conducts live inspection (via TinyFish or read-only HTTP fetch):
   - **Active Listing:** `VERIFIED_ACTIVE` (mapped to `SUPPORTED` in legacy contract).
   - **Closed Listing:** `VERIFIED_CLOSED` ("Position is marked as closed or filled").
   - **Expired Listing:** `VERIFIED_EXPIRED` ("Requisition has expired").
   - **Generic Search / Homepage Only:** `UNVERIFIED` ("General search directory, not an individual requisition").
   - **Provider Failure / Timeout:** `CHECK_FAILED` ("External lookup service timed out").

---

## 3. TINYFISH LIVE RESEARCH INTEGRATION

AheadGuard AI integrates directly with TinyFish's browser automation agent via Server-Sent Events (SSE):

* **Endpoint:** `https://agent.tinyfish.ai/v1/automation/run-sse`
* **Security Constraints:** Strict read-only operations. No automated form completion, credential submission, payment execution, or file downloads.
* **Adversarial Web Defense:** Web content retrieved during crawls is treated as untrusted text and stripped of prompt injection attempts (e.g. `ignore all previous instructions`).
* **Streaming Protocol:** Handles `STARTED`, `PROGRESS`, `STREAMING_URL`, `HEARTBEAT`, and terminal `COMPLETE` events.
* **Failure Handling:** If the SSE stream disconnects prematurely or returns an error, the orchestrator records `CHECK_FAILED` for that specific external research dimension, preserves all directly observed message evidence, and prevents unjustified `LOW OBSERVED RISK` verdicts.

---

## 4. RECRUITER VERIFICATION DIMENSIONS

To prevent deceptive display names and email spoofing from creating false confidence, recruiter analysis is split into four distinct dimensions:

| Dimension | Scope | Permitted Statuses | Key Decision Rule |
| :--- | :--- | :--- | :--- |
| **Claimed Identity** | Message text | `OBSERVED` | Captures name, designation, channel, and handle. |
| **Email-Domain Consistency** | Technical domain alignment | `MATCHED_DOMAIN`, `DOMAIN_MISMATCH`, `GENERIC_EMAIL_PROVIDER`, `NOT_PROVIDED` | Evaluates whether sender domain matches authenticated corporate domain. |
| **Individual Identity** | Public corroboration | `VERIFIED_IDENTITY`, `PARTIALLY_CORROBORATED`, `UNVERIFIED`, `CONTRADICTED` | **A matching domain never verifies individual identity.** |
| **Employer Affiliation** | Official relationship | `VERIFIED_AFFILIATION`, `SUPPORTED_AFFILIATION`, `UNVERIFIED_AFFILIATION` | Matching domain yields `SUPPORTED_AFFILIATION`, never `VERIFIED`. |

---

## 5. PAYMENT EXTRACTION & CONTRADICTION ENGINE

* **Canonical Payment Object:** Captures `requested`, `amount`, `currency`, `amountDisclosed`, `feeCategory`, `paymentMethod`, `upiId`, `mandatory`, `refundableClaimed`, and `deadline`.
* **Missing Amount Rule:** `payment.requested = Boolean(fee.detected || paymentAmount)`. When an offer demands a registration fee without disclosing the numeric amount, `amountDisclosed: false` is preserved, status is marked `OBSERVED`, and the report warns against mandatory upfront fees.
* **Policy Contradiction:** When an employer's authoritative no-fee policy is confirmed (via live crawl or cached reference), the payment request status transitions to `CONTRADICTED`.

---

## 6. DETERMINISTIC 4-TIER RISK ENGINE

The risk assessment engine executes deterministic policy rules without nondeterministic generative drift:

1. **HIGH RISK:**
   - Mandatory payment request directly contradicted by authenticated corporate policy.
   - Verified employer impersonation or lookalike domain weaponization.
   - High-severity combination of payment demand, artificial urgency, and paywalled offer letter.
2. **SUSPICIOUS:**
   - Mandatory upfront recruitment fee from an unverified employer or without corporate policy contradiction.
   - Genuine corporate vacancy paired with an unverified recruiter channel (Telegram, generic webmail).
   - Artificial payment deadlines or offer-letter paywalls.
3. **UNKNOWN:**
   - Missing external research or incomplete verification checks (`CHECK_FAILED`).
   - Benign job offer from an unverified company with zero red flags or payment demands.
   - Inconclusive corroboration. *Unknown is never safe.*
4. **LOW OBSERVED RISK:**
   - Issued ONLY when positive evidence corroborates an active vacancy requisition on an authenticated corporate portal with domain consistency and zero payment requests.
   - Specifically scoped to the public job listing, clearly distinguished from unsolicited personalized recruiter communications.

---

## 7. DATABASE, DURABLE JOBS & PLATFORM INTEGRATIONS

* **Database Engine:** Neon Serverless PostgreSQL with pgvector and pooled connection handling. Falls back gracefully to memory/ephemeral storage if connection limits are reached.
* **Durable Job Worker:** Implements deduplication, retry with exponential backoff, worker heartbeat monitoring, and idempotent execution across asynchronous investigations.
* **Platform Integrations:** Multi-channel ingest supports Webhooks (Telegram, WhatsApp Business, Instagram Professional, Discord, Slack, Gmail), Chrome Extension, and Mobile iOS/Android Share Target workflows, all governed by strict origin validation and token privacy guards.
