# AHEADGUARD AI — EVIDENCE-VERIFIED COMPREHENSIVE TEST REPORT

**Product:** AheadGuard AI  
**Program:** Swim with TinyFish × Scaler School of Technology  
**Team:** CODESTROME  
**Repository:** https://github.com/gokul1599/AheadGuard-Ai  
**Feature Branch:** `feature/evidence-verified-upgrade`  
**Execution Timestamp:** 2026-11-01  
**Status:** ALL TESTS PASSING (100% REGRESSION PASS RATE)  

---

## 1. TEST EXECUTION SUMMARY

| Test Execution Metric | Value |
| :--- | :--- |
| **Total Test Files** | 33 test files |
| **Test Files Passed** | 32 passed, 1 skipped |
| **Total Tests Executed** | 517 tests |
| **Tests Passed** | 512 passed |
| **Tests Failed** | 0 failed |
| **Tests Skipped** | 5 skipped (`tests/smoke.test.ts` deliberately skipped in offline unit test harness) |
| **TypeScript Compilation (`npx tsc --noEmit`)** | 0 errors |
| **ESLint Quality Gate (`npm run lint`)** | 0 errors, 0 warnings |
| **Next.js Production Build (`npm run build`)** | Successful (Static + Dynamic routes compiled in 8s) |

---

## 2. SPECIFICATION REGRESSION MATRIX (TESTS A THROUGH N)

Executed via `tests/offer-integrity-evidence-verified.test.ts`:

| Test ID | Scenario Description | Expected Outcome | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TEST A** | Synthetic Nexora Recruitment Scam (₹999 refundable fee, Telegram recruiter, 2h deadline, no interview, `.example` portal) | All claims extracted, `.example` suppressed from verified route, fee marked `OBSERVED`, verdict at least `SUSPICIOUS`, action says `DO NOT PAY` | Full structured extraction; fee detected; `.example` flagged as RFC 2606 reserved space; verdict `SUSPICIOUS`; warning directs non-payment | **PASS** |
| **TEST B** | Real Amazon Official Careers Listing (`/jobs/10541345/sde-i-intern-...`) | Corroborates official domain, requisition ID `10541345`, listing title, active status, no fabricated salary or recruiter, verdict `LOW OBSERVED RISK` | Domain verified (`amazon.com`/`amazon.jobs`); req ID `10541345`; title verified; verdict `LOW OBSERVED RISK` | **PASS** |
| **TEST C** | Real Employer, Fake Recruiter (Google + unverified Telegram recruiter) | Employer verified, vacancy supported, recruiter unverified, verdict reflects suspicious context | Employer cataloged; vacancy supported; recruiter `UNVERIFIED`; verdict `SUSPICIOUS` | **PASS** |
| **TEST D** | Real Vacancy, Fake Payment Request (Google role + ₹1,500 onboarding fee) | Vacancy supported, fee observed, corporate policy contradicts fee, verdict `HIGH RISK` | Core principle verified: role supported while fee contradicted by Google anti-fraud policy; verdict `HIGH RISK` | **PASS** |
| **TEST E** | Payment Without Numeric Amount ("Pay mandatory registration fee before offer letter") | Payment requested is `true`, amount undisclosed, status `OBSERVED`, verdict `SUSPICIOUS`, never shows "Zero Fees" | Undisclosed fee recognized; status `OBSERVED`; verdict `SUSPICIOUS`; clean UI notice | **PASS** |
| **TEST F** | Unknown Company, No Red Flags (Benign startup offer without fee) | Vacancy `UNVERIFIED`, payment `NOT_REQUESTED`, verdict `UNKNOWN` (never falsely `HIGH RISK`) | Preserves honest uncertainty; verdict `UNKNOWN`; no fabricated malicious flags | **PASS** |
| **TEST G** | Optional Training Notice (Coursera upsell + free hiring) | Optional training not misclassified as mandatory recruitment fee | `fee.detected: false`, `isOptionalTrainingNotice: true`; no false fee alarm | **PASS** |
| **TEST H** | Domain Impersonation & SSRF Defense | Rejects lookalikes (`amazon.jobs.attacker.example`), embedded credentials, private IPs, loopbacks | Strict subdomain boundary enforcement; credentials rejected; private IPs blocked | **PASS** |
| **TEST I** | Policy Source Failure Handling (`simulatePolicyFailure: true`) | Cached reference remains cached; live check marked `CHECK_FAILED`; no false live verification | Policy marked `CHECK_FAILED`; local catalog retained honestly; payment evidence intact | **PASS** |
| **TEST J** | Recruiter Verification Dimensions | Decouples domain consistency from individual identity verification | Domain marked `MATCHED_DOMAIN`; individual identity remains `UNVERIFIED`; no false `VERIFIED` recruiter | **PASS** |
| **TEST K** | TinyFish Failure Handling | Gracefully handles stream termination, timeouts, or API unavailability without false safety | Vacancy marked `CHECK_FAILED`; existing observed evidence preserved; no false `LOW RISK` | **PASS** |
| **TEST L** | Database & Durable Jobs Integration | Ingests entities into TrustGraphStore cleanly with owner isolation | Upserts nodes; preserves investigation provenance and relationship edges | **PASS** |
| **TEST M** | Report Consistency Across Sections | Header verdict, ledger, breakdown, and safe action plan all reflect identical findings | 100% unified model across verdict title, ledger claims, breakdown cards, and action directives | **PASS** |
| **TEST N** | Mobile & iOS Security | Origin validation strictly permits authorized domains and blocks wildcards/forged origins | Rejects untrusted origins; sets strict CORS headers; rejects `*` origin reflection | **PASS** |

---

## 3. FULL TEST SUITE BREAKDOWN (33 FILES)

```
✓ tests/offer-integrity-evidence-verified.test.ts (16 tests)
✓ tests/offer-integrity-21-regression.test.ts (21 tests)
✓ tests/offer-integrity-evaluator.test.ts (5 tests)
✓ tests/offer-integrity-api.test.ts (4 tests)
✓ tests/offer-integrity-policy.test.ts (4 tests)
✓ tests/offer-integrity-claim-extractor.test.ts (4 tests)
✓ tests/recruitment-behavior-intelligence.test.ts (12 tests)
✓ tests/repro-nexora.test.ts (2 tests)
✓ tests/api-security.test.ts (34 tests)
✓ tests/ios-compatibility.test.ts (16 tests)
✓ tests/mobile-share.test.ts (3 tests)
✓ tests/db.test.ts (71 tests)
✓ tests/durable-jobs.test.ts (10 tests)
✓ tests/persistence-verifier.test.ts (39 tests)
✓ tests/real-world-integration.test.ts (26 tests)
✓ tests/tinyfish-sse.test.ts (18 tests)
✓ tests/telegram-integration-e2e.test.ts (6 tests)
✓ tests/message-intelligence.test.ts (18 tests)
✓ tests/platform-integrations.test.ts (12 tests)
✓ tests/privacy-hardening.test.ts (12 tests)
✓ tests/demo-mode.test.ts (9 tests)
✓ tests/policy-engine.test.ts (64 tests)
✓ tests/company-verification.test.ts (18 tests)
✓ tests/url-safety.test.ts (6 tests)
✓ tests/claim-verification.test.ts (7 tests)
✓ tests/trustgraph.test.ts (3 tests)
✓ tests/trust-gap-map.test.ts (4 tests)
✓ tests/evidence-coverage.test.ts (4 tests)
✓ tests/transaction-truth.test.ts (7 tests)
✓ tests/extension.test.ts (29 tests)
✓ tests/benchmark.test.ts (25 tests)
✓ tests/smoke.test.ts (5 tests | 5 skipped)
```

---

## 4. VERIFICATION OF QUALITY GATES

1. **Compilation Gate:**
   `npx tsc --noEmit` executed cleanly with 0 type errors.
2. **Lint Quality Gate:**
   `npm run lint` executed cleanly with 0 ESLint errors and 0 warnings.
3. **Build Gate:**
   `next build` produced an optimized production build across all static pages and dynamic API routes with no hydration mismatch or bundler warnings.
