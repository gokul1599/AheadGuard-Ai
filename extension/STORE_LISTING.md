# AheadGuard AI — Chrome Web Store Submission Package

**Extension Name:** AheadGuard AI — Proactive Digital Safety Guardian  
**Target Release Version:** `2.1.0`  
**Manifest Version:** 3  
**Package Artifact:** `aheadguard-extension-v2.1.0.zip`  
**Official Backend:** `https://aheadguard-ai.vercel.app`

---

## 1. Store Metadata & Descriptions

### Single-Purpose Statement
AheadGuard AI investigates suspicious web destinations, unverified recruitment offers, and misleading payment links before you commit sensitive actions, credentials, or funds.

### Short Description (Max 132 characters)
Your AI checks first. You act with confidence. Pre-action digital safety assistant investigating suspicious links and offers.

### Detailed Description
AheadGuard AI is an evidence-first proactive digital trust and scam intelligence assistant that accompanies you across the web.

Instead of passively reacting after fraud occurs, AheadGuard investigates suspicious links, job offers, payment traps, and deceptive forms before you commit sensitive actions.

#### Key Features:
• **Before-You-Act Investigation**: Automatically evaluates current tab destinations against corporate registries, lookalike domain indicators, and credential-harvesting markers.
• **Offer Integrity Intelligence (Check Before You Pay)**: Highlight suspicious internship or job offer emails and right-click to verify whether the vacancy is genuine and whether requested interview/registration fees contradict official corporate hiring policies.
• **Claim-to-Evidence Trust Gap Ledger**: Connects every claim directly to observable web infrastructure facts, published policies, and authoritative primary sources.
• **Safe Action Planner**: Delivers concrete, step-by-step guidance and authentic corporate application routes whenever a scam indicator is identified.
• **Privacy-by-Design**: Zero keystroke logging. Zero password or OTP collection. Analysis executes in an isolated read-only remote sandbox.

*Core Trust Principle:* **The internship can be real while the payment request is false.** AheadGuard helps you spot the difference.

---

## 2. Permission Justifications for Chrome Web Store Reviewers

| Permission | Reviewer Justification |
| :--- | :--- |
| `activeTab` | Required to access the URL and title of the currently focused tab when the user opens the AheadGuard popup or triggers an investigation. Does not grant background access to tabs. |
| `storage` | Required to persist user preferences (e.g., pause history, toggle proactive badge notifications) and cache recent verification verdicts locally to prevent redundant API queries. |
| `webNavigation` | Required to receive `onCommitted` navigation events for top-level frames only, enabling AheadGuard to update the toolbar risk badge (Green / Yellow / Red) when navigating to new destinations. |
| `contextMenus` | Required to add user-initiated context menu items ("Investigate Selected Text", "Verify Job / Internship Offer (Before You Pay)", and "Investigate Link Destination"). |
| `host_permissions` (`https://aheadguard-ai.vercel.app/*`) | Required to communicate with the official AheadGuard AI production verification API and Neon database backend. |

---

## 3. Data Handling & Privacy Policy Disclosures

### Single Purpose Compliance
The extension has a single, clearly defined purpose: providing proactive digital trust, scam verification, and offer integrity intelligence to protect users from web deception and financial fraud.

### Data Privacy Statements
- **No Keystroke Monitoring**: AheadGuard does not record keyboard inputs, passwords, or form entries.
- **No Personal Message Interception**: The extension only processes URLs and text that the user explicitly selects or navigates to.
- **No Financial Data Collection**: AheadGuard never requests or stores credit card numbers, bank credentials, or UPI PINs.
- **Redaction of PII**: Email addresses, phone numbers, and potential sensitive tokens are automatically redacted prior to report persistence.
- **No Sale of Data**: User browsing data is never sold, leased, or transferred to third-party data brokers or advertisers.

---

## 4. Visual Asset Checklist for Chrome Web Store

- [x] **Store Icon**: `icons/icon128.png` (128x128 px, PNG format with alpha channel)
- [x] **Small Icon**: `icons/icon48.png` (48x48 px)
- [x] **Toolbar Icon**: `icons/icon16.png` (16x16 px)
- [ ] **Screenshot 1** (1280x800): AheadGuard Popup inspecting an active destination with Risk Badge.
- [ ] **Screenshot 2** (1280x800): Offer Integrity verification showing "Role SUPPORTED / Fee CONTRADICTED".
- [ ] **Screenshot 3** (1280x800): Trust Gap Map claim-by-claim evidence ledger.
- [ ] **Small Promo Tile** (440x280 px): Brand shield logo with tagline "Your AI checks first. You act with confidence."
- [ ] **Marquee Banner** (1400x560 px): Wide visual depicting cross-platform digital trust intelligence.

---

## 5. Developer Dashboard Submission Steps

1. Sign in to the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole).
2. Click **"New Item"** and upload `aheadguard-extension-v2.1.0.zip`.
3. Fill in the **Store Listing** fields using the descriptions in Section 1.
4. Set the Category to **Productivity** (Secondary: **Developer Tools**).
5. In the **Privacy** tab:
   - Paste the justifications from Section 2 for `activeTab`, `storage`, `webNavigation`, and `contextMenus`.
   - Provide the public Privacy Policy URL: `https://aheadguard-ai.vercel.app/`.
   - Certify that the extension complies with the Developer Program Policies.
6. Upload screenshots and promo tiles from Section 4.
7. Click **"Submit for Review"**.
