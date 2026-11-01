# AHEADGUARD AI — RECRUITMENT SCAM DETECTION ROOT CAUSE ANALYSIS

**Product:** AheadGuard AI  
**Release Targets:** Version 2.1 (Digital Trust Intelligence Platform) & Version 3.0 (Embedded Digital Trust Intelligence Agent)  
**Investigation ID:** `ROOT-CAUSE-REC-2026-001`  
**Severity:** CRITICAL  
**Status:** RESOLVED & VERIFIED  

---

## 1. EXECUTIVE SUMMARY

An end-to-end vulnerability audit of the AheadGuard AI Offer Integrity & Message Investigation pipeline revealed a critical flaw: when presented with a high-consequence synthetic recruitment scam—specifically a demand for an upfront refundable fee (₹2,999) under strict 24-hour urgency, no interview assessment, paywalled offer letter/employee ID, unverified Telegram recruiter (`@Rahul_Nexora_HR`), and a reserved `.example` domain—the platform returned an inconclusive `Unknown` verdict with `0` observed claims and an ambiguous `"UnknownVERIFIED"` UI status.

This failure allowed dangerous recruitment fraud indicators to be obscured, leaving vulnerable job seekers unprotected. The failure stemmed from brittle regex extraction, priority inversions between external registries and behavioral evidence, truncation of long messages, and UI status concatenation defects.

---

## 2. THE TARGET TEST CASE (SYNTHETIC NEXORA TECHNOLOGIES)

The synthetic vulnerability payload consisted of:
```text
Congratulations! You have been shortlisted for the AI & Machine Learning Internship at Nexora Technologies Pvt. Ltd.

Your internship duration will be 3 months, with a monthly stipend of ₹45,000.

To confirm your selection, you must complete mandatory employee verification by paying a refundable registration and onboarding fee of ₹2,999.

Payment must be completed within 24 hours through the UPI ID shared by your recruitment coordinator.

After payment confirmation, your digital offer letter and employee ID will be generated. No interview is required for this position.
```
- **Claimed Organization:** Nexora Technologies Pvt. Ltd.
- **Claimed Role:** AI & Machine Learning Intern — Work From Home
- **Recruiter:** Rahul Sharma — @Rahul_Nexora_HR (Telegram)
- **Application URL:** `https://nexora-careers.example/ai-internship-apply`
- **Vacancy URL:** `https://nexora.example/careers`

---

## 3. ROOT CAUSE BREAKDOWN

### 3.1 Defect 1: Brittle Regex in `lib/message-intelligence.ts`
The legacy `detectRecruitmentFee()` and `detectPaymentRisks()` engines relied on brittle regexes:
```typescript
// Legacy regex required specific verbs immediately followed by fee names:
/(?:pay|deposit|transfer|send|submit)\s+(?:an?|the|any|a)?\s*(?:application|registration)\s+fees?/i
```
**Failure Mechanics:**
1. The synthetic scam used natural language variation: `"paying a refundable registration and onboarding fee of ₹2,999"`.
   - The participle `"paying"` was not matched by `(?:pay|deposit|transfer)`.
   - The phrase `"registration and onboarding fee"` inserted `"and onboarding"`, which broke strict adjacency.
2. The legacy regex for payment methods required `"to UPI ID"` or `"UPI: "`, failing to match indirect instructions like `"through the UPI ID shared by your recruitment coordinator"`.
3. Consequently, `detectRecruitmentFee()` and `detectPaymentRisks()` returned `undefined` and `[]`, completely ignoring the ₹2,999 fee demand.

### 3.2 Defect 2: Premature Truncation of Message Analysis Input
In `lib/claims-evaluator.ts`, message text excerpts were hard-limited to 400 characters:
```typescript
// Legacy truncation in claims-evaluator.ts:
messageExcerpt: messageData.redactedText.slice(0, 400)
```
In real recruitment scam messages, attackers place formal corporate preambles first and position the urgent fee demand at the end. In the Nexora message, the 400-character cut occurred directly inside the payment instruction (`"Payment must be completed within 24 hours through the UPI I..."`), cutting off the payment channel and the subsequent clauses declaring `"no interview is required"` and paywalling the offer letter.

### 3.3 Defect 3: Priority Inversion (External Registry Overriding Behavioral Evidence)
In `lib/offer-integrity/offer-evaluator.ts`:
1. The pipeline evaluated the employer against external registries (`verifyCompanyIdentity()`).
2. When the employer was unknown (e.g., Nexora Technologies), the pipeline defaulted to `riskOutcome = "Unknown"`.
3. The platform lacked an independent **Behavioral Evidence Layer**. If the employer registry check failed or was inconclusive, observable malicious signals (upfront payment, 24h coercion, direct P2P messaging, reserved domain) were suppressed from driving the minimum risk outcome.

### 3.4 Defect 4: Status Concatenation & Inadequate Outcomes in UI
Two distinct UI bugs contributed to the misleading report presentation:
1. **`app/page.tsx:1142`**:
   ```tsx
   <div className="status-bar" role="status" aria-live="polite">
     <span className={loading ? "status-dot blinking" : "status-dot"} />
     <span>{status}</span>
     <span className="status-pill-end">{loading ? "STREAMING" : "VERIFIED"}</span>
   </div>
   ```
   When `status` rendered `"Investigation completed · Unknown"`, the right-aligned status pill displayed `"VERIFIED"`, causing visual fusion into `"Investigation completed · UnknownVERIFIED"`. Falsely labeling an unverified or high-risk investigation as `"VERIFIED"` violated digital safety principles.
2. **`components/OfferIntegrityCard.tsx:101`**:
   The outcome pill function `getRiskOutcomePill()` omitted a `case "Unknown"` handler, silently falling into default:
   ```tsx
   default:
     return <span className="intel-pill pill-match">LOW OBSERVED RISK</span>;
   ```
   An `Unknown` investigation was therefore rendered with a green `LOW OBSERVED RISK` badge!

### 3.5 Defect 5: Unsafe Fallback in Safe Action Planner
When an unverified vacancy contained a submitted URL ending in `.example` (reserved by RFC 2606 for synthetic documentation):
```typescript
verifiedApplicationRoute: vacancyDetail.matchedListingUrl || vacancyDetail.officialCareersUrl || rawAppUrl
```
The platform recommended visiting the untrusted `.example` link as the "verified application route", directing users straight to the fraudulent destination.

---

## 4. IMPACT ASSESSMENT

| Pipeline Component | Flawed Behavior | Correct Production Behavior |
| :--- | :--- | :--- |
| **Fee Extraction** | Missed `"paying ... registration and onboarding fee of ₹2,999"` | Structured extraction of ₹2,999 INR via UPI as `OBSERVED` evidence |
| **Urgency Extraction** | Ignored `"within 24 hours"` | Explicit `deadline_urgency` claim categorized as `OBSERVED` |
| **Process Anomalies** | Ignored `"No interview is required"` & offer paywall | Flagged as `interview_process` and `document_request` anomalies |
| **Risk Verdict** | Inconclusive `Unknown` with 0 claims | Deterministic `Suspicious` (or `High risk` if contradictory) |
| **Safe Action Plan** | Pointed candidate to `nexora-careers.example` | Omitted unverified routes, instructed refusal of fee and independent contact |
| **Status Bar UI** | Rendered `"UnknownVERIFIED"` | Displays actual outcome (`SUSPICIOUS` / `HIGH RISK`), never false `VERIFIED` |
