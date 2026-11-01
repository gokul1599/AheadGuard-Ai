# AHEADGUARD AI — EVIDENCE-VERIFIED ROOT CAUSE ANALYSIS & RESOLUTION REPORT

**Project:** AheadGuard AI  
**Program:** Swim with TinyFish × Scaler School of Technology  
**Engineering Team:** CODESTROME  
**Repository:** https://github.com/gokul1599/AheadGuard-Ai  
**Production URL:** https://aheadguard-ai.vercel.app/  
**Investigation ID:** `EVIDENCE-VERIFIED-P0-ROOT-CAUSE-2026`  
**Classification:** P0 Critical Architecture & Intelligence Remediation  
**Status:** RESOLVED, VERIFIED & PASSING IN AUTOMATED REGRESSION SUITE  

---

## 1. EXECUTIVE SUMMARY & PRODUCTION CONTEXT

AheadGuard AI investigated a series of subtle, high-consequence edge cases where the core non-negotiable trust principles were violated by the underlying Offer Integrity 2.1 pipeline:
1. **"THE INTERNSHIP CAN BE REAL WHILE THE PAYMENT REQUEST IS FALSE."**
2. **"UNKNOWN IS NOT SAFE."**
3. Missing evidence must never be transformed into proof of safety.
4. An authenticated corporate domain match must never promote an individual recruiter to `VERIFIED`.
5. An undisclosed payment amount must never erase a directly observed mandatory fee request.

Prior to this upgrade, several structural flaws allowed deceptive recruitment tactics to evade detection or produce contradictory reports. This root-cause analysis documents the exact vulnerabilities identified across 6 core components, their reproduction pathways, the architectural solutions implemented, and the automated verification suite demonstrating 100% resolution.

---

## 2. AUDIT OF VULNERABILITIES & ROOT CAUSES

### A. Vacancy Requisition Verification vs. Generic Domain Substring Match
* **Affected Component:** `lib/offer-integrity/offer-evaluator.ts` (Lines 67–150)
* **Vulnerability Description:** The evaluator previously used unsafe domain substring matching (`directHost.includes("amazon.jobs")`) and treated any matching domain as proof that the individual vacancy was `SUPPORTED`. It fabricated vacancy titles (e.g. `${roleTitle} - Active Official Listing`), duration, eligibility, and active status without actually retrieving the page or verifying requisition existence.
* **Security & Fraud Risk:** 
  - Substring vulnerability: An attacker domain such as `https://amazon.jobs.attacker.example/careers` was matched as legitimate Amazon jobs.
  - Expired / fabricated listings: An expired requisition or a generic homepage (`https://careers.google.com/`) was erroneously returned as `VERIFIED_ACTIVE`, obscuring fake roles.
* **Root Cause:** Conflation between *corporate domain ownership* and *individual job requisition existence*.
* **Implemented Fix:** Created a dedicated vacancy verification service (`lib/offer-integrity/vacancy-verifier.ts`). Implemented strict hostname matching (`isApprovedEmployerHost`), applicant tracking system (ATS) tenant alignment verification (`verifyAtsEmployerAlignment`), requisition ID extraction (`extractRequisitionId`), and live page inspection via TinyFish and safe HTTP fetch. Vacancy status is now accurately typed across `VERIFIED_ACTIVE`, `VERIFIED_CLOSED`, `VERIFIED_EXPIRED`, `PARTIAL_MATCH`, `UNVERIFIED`, and `CHECK_FAILED`.

---

### B. Recruiter Conflation & False Individual Verification
* **Affected Component:** `lib/offer-integrity/offer-evaluator.ts` (Lines 200–265, 365–380)
* **Vulnerability Description:** When an offer came from a corporate email domain (e.g. `sarah@microsoft.com`), the evaluator set `senderDetail.affiliationStatus = "SUPPORTED"`, but then in the claims ledger mapped both `recruiter_affiliation` AND `recruiter_identity` to `"VERIFIED"`.
* **Security & Fraud Risk:** Having an email domain match corporate records does not verify the individual identity, employment authorization, or legitimacy of a personalized offer letter. It falsely reassured users that an individual had been authenticated.
* **Root Cause:** Failure to decouple the 4 distinct recruiter dimensions:
  1. *Claimed Identity* (Observed name, handle, designation)
  2. *Email-Domain Consistency* (`MATCHED_DOMAIN`, `GENERIC_EMAIL_PROVIDER`, `DOMAIN_MISMATCH`)
  3. *Individual Identity* (`UNVERIFIED`, `PARTIALLY_CORROBORATED`, `VERIFIED_IDENTITY`)
  4. *Employer Affiliation* (`SUPPORTED_AFFILIATION`, `UNVERIFIED_AFFILIATION`)
* **Implemented Fix:** Decoupled recruiter dimensions in `lib/offer-integrity/types.ts` and `offer-evaluator.ts`. When email domains align with official corporate registries, the report records:
  `"Corporate email-domain consistency observed; individual recruiter identity and authorization remain independently unverified."`
  Individual recruiter identity claims strictly remain `UNVERIFIED`.

---

### C. Undisclosed Payment Amount Masking ("Zero Fees Requested" Bug)
* **Affected Component:** `lib/recruitment-intelligence.ts` (Line 445) and `lib/offer-integrity/offer-evaluator.ts` (Line 175)
* **Vulnerability Description:** 
  1. Brittle regex in `genericFeePhrase` (`/(?:pay|deposit|send|transfer)\s+(?:a\s+)?(?:mandatory\s+)?.../i`) failed to match phrases with articles other than "a" (e.g., *"Pay the mandatory registration fee before receiving your offer letter"* or *"Pay the registration fee"*).
  2. In `offer-evaluator.ts`, the payment evaluation check was `if (paymentAmount)`. When an offer explicitly demanded a mandatory recruitment fee without disclosing the numeric amount, `paymentAmount` was `undefined`. This caused the evaluator to bypass payment analysis, set `paymentRequested = false`, and render `"Zero Fees Requested in Communication"`.
* **Security & Fraud Risk:** Job offers that withhold offer letters until an undisclosed "registration deposit" is paid were classified as `LOW OBSERVED RISK` or benign, completely blinding users to the upfront paywall scam.
* **Root Cause:** Rigid coupling of payment detection to numeric regex capture rather than behavioral fee requests.
* **Implemented Fix:** 
  1. Expanded `genericFeePhrase`, `mandatoryFeePhrase`, and `paymentForDocPhrase` in `lib/recruitment-intelligence.ts`.
  2. Evaluator now uses `const isPaymentRequested = Boolean(extracted.recruitmentAnalysis.fee.detected || paymentAmount)`.
  3. Added `amountDisclosed: boolean` to `PaymentRequirementDetail` and `CanonicalOfferExtraction`. Undisclosed fees render as `"Mandatory recruitment fee (amount undisclosed in communication)"` with status `OBSERVED` or `CONTRADICTED`.

---

### D. Static Policy Cache Promoted as Live Verification
* **Affected Component:** `lib/offer-integrity/policy-verifier.ts` (Lines 164–178)
* **Vulnerability Description:** The static catalog `ENTERPRISE_RECRUITMENT_POLICIES` was returning `policyStatus: "POLICY_CONFIRMED_NO_FEE"` unconditionally, presenting hardcoded policy quotes as freshly retrieved live evidence from the target employer. Furthermore, external failure simulations had no mechanism to report provider failure while keeping cached data honest.
* **Root Cause:** Conflation between *cached reference catalog* and *live external policy retrieval*.
* **Implemented Fix:** 
  1. Separated cached entries (`sourceType: "CACHED_CATALOG"`, `CACHED_POLICY_REFERENCE`) from live crawl results (`sourceType: "LIVE_RETRIEVAL"`, `LIVE_POLICY_CONFIRMED_NO_FEE`).
  2. Implemented `simulateFailure` handling: when live policy discovery fails, status is explicitly recorded as `CHECK_FAILED`, explaining that external retrieval failed while noting the local reference catalog entry without fabrication.

---

### E. Disconnected TinyFish Live Research in Dedicated Offer Integrity
* **Affected Component:** `lib/tinyfish.ts` and `lib/offer-integrity/offer-evaluator.ts`
* **Vulnerability Description:** While TinyFish SSE streaming was integrated into the general URL investigator (`/api/investigate`), the dedicated Offer Integrity evaluator (`evaluateOfferIntegrity`) ran entirely offline, neither invoking TinyFish for live requisition validation nor capturing live browser artifacts.
* **Root Cause:** Pipeline isolation between general investigation SSE workers and structured claim evaluation.
* **Implemented Fix:** 
  1. Extended `TinyFishRunOptions` with optional `goal?: string` to support specialized read-only research tasks (vacancy lookup, anti-fraud policy discovery).
  2. Connected TinyFish directly to `verifyVacancyRequisition` in `lib/offer-integrity/vacancy-verifier.ts` and `offer-evaluator.ts`.
  3. Added `tinyFishResearchOutcome` to `OfferIntegrityReport` tracking events count, streaming status, discovered sources, and isolated execution.
  4. Added graceful fallback to `CHECK_FAILED` when external browser streaming terminates prematurely or times out.

---

### F. UI Misrepresentation & Concatenation Defects
* **Affected Component:** `components/OfferIntegrityCard.tsx`
* **Vulnerability Description:** 
  1. The UI collapsed recruiter verification into a single binary badge, creating misleading "VERIFIED" impressions for unverified recruiters.
  2. Undisclosed fee amounts caused interpolation of `"INR undefined"`.
  3. No visual indicator showed whether TinyFish live web research took place.
* **Implemented Fix:**
  1. Card 3 in Component Breakdown now renders independent tags for Channel, Domain Consistency, and Identity.
  2. Undisclosed fees render clean explanatory text.
  3. Added live research indicator banner showing TinyFish execution status and event count.

---

## 3. VERIFICATION & REGRESSION EVIDENCE

All 14 comprehensive regression scenarios from Section 18 of the specification have been implemented in `tests/offer-integrity-evidence-verified.test.ts` and verified:
* **TEST A (Synthetic Nexora Scam):** PASS
* **TEST B (Real Amazon Careers Listing):** PASS
* **TEST C (Real Employer, Fake Recruiter):** PASS
* **TEST D (Real Vacancy, Fake Fee Demand):** PASS
* **TEST E (Undisclosed Amount):** PASS
* **TEST F (Unknown Company, Benign):** PASS
* **TEST G (Optional Training):** PASS
* **TEST H (Domain Impersonation & SSRF Defense):** PASS
* **TEST I (Policy Source Failure):** PASS
* **TEST J (Recruiter Verification Dimensions):** PASS
* **TEST K (TinyFish Failure Handling):** PASS
* **TEST L (TrustGraph Persistence):** PASS
* **TEST M (Report Consistency):** PASS
* **TEST N (Mobile & iOS Security):** PASS

**Suite Totals:** 33 test files passed, 512 tests passed, 0 failures, 5 skipped (smoke tests).  
**TypeScript Typecheck:** 0 errors (`npx tsc --noEmit`).  
**Lint Check:** 0 errors, 0 warnings (`npm run lint`).  
**Production Build:** Clean Next.js 15 build (`npm run build`).
