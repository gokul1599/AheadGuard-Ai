# AheadGuard AI — Pre-Action Digital Safety Guardian

> **Your AI checks first. You act with confidence.**

AheadGuard AI is a proactive digital safety guardian that investigates unknown destinations, phishing traps, and deceptive links **before** you commit sensitive actions. It deploys an isolated, read-only remote browser sandbox to inspect live behavior, evaluates observable evidence against a deterministic policy engine, simulates consequences with **Action Preview**, and maintains a privacy-first **Evidence Ledger**.

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
     - 🟢 **Low observed risk**: Benign destination verified with no warning signals found in this probe (*"Low observed risk is not an absolute guarantee of safety"*).
     - ⚪ **Unknown**: Destination could not be verified due to timeouts, network barriers, or unreachable targets.

3. **Action Preview ("Before You Commit")**:
   - Consequence simulation model detailing what would happen if a user proceeds.
   - Highlights proposed actions, consequences of proceeding, and specific risk factors.
   - Suggests a deterministic, safer alternative action (e.g., direct navigation via verified bookmarks).

4. **Evidence Explorer & Provenance**:
   - Strict separation between **Observed Facts** (direct sandbox observations) and **Model Interpretations** (clearly labeled AI inferences with confidence ratings).
   - Detailed evidence items with verifiable provenance badges (`TINYFISH_DOM`, `HTTP_ANALYSIS`, `NETWORK_REDIRECT`, etc.).

5. **Local Evidence Ledger**:
   - Client-side history stored exclusively in user-controlled browser storage.
   - Never transmitted to external analytics or centralized databases.
   - One-click pause/resume recording toggle and instant ledger wipe.

6. **Chrome Extension (Manifest V3)**:
   - Real-time active tab detection with automatic filtering of internal (`chrome://`) schemes.
   - Collapsible manual URL checker.
   - Compact Action Preview and evidence summaries.
   - Configurable settings drawer (navigation awareness, ledger pause, customizable backend endpoint).
   - "Return to Safety" safe navigation action.

---

## Security Architecture & Defenses

- **Strict Server-Side Isolation**: All external browser interactions occur inside an isolated remote sandbox. The investigator will never log in, submit forms, execute files, or follow instructions attempting to hijack the investigation.
- **SSRF & Loopback Defense**: Pre-flight validation blocks loopback (`127.0.0.1`, `localhost`), link-local (`169.254.0.0/16`), private RFC 1918 subnets, cloud metadata endpoints (`169.254.169.254`), and non-standard schemes (`javascript:`, `file:`, `data:`).
- **Redirect Chain Validation**: Follows redirection targets and re-evaluates `observed_final_url` against SSRF rules to prevent open-redirect escape attacks.
- **Defensive CORS Allowlist**: Strictly validates incoming Chrome extension origins against configured 32-letter extension IDs (`getAllowedExtensionIds`) with fail-safe rejection (`403 Forbidden`).
- **Payload Size Limits**: Rejects requests exceeding 16KB (`413 Payload Too Large`) to protect against buffer overflow and denial-of-service attempts.
- **Backend Endpoint Validation**: Chrome extension validates user-supplied backend endpoints to prevent rogue redirection to unauthorized servers.
- **Safe Error Redaction**: Upstream provider errors, API keys, and stack traces are redacted before delivery to the client.

---

## Project Structure

```
aheadguard-mvp-starter/
├── app/
│   ├── api/
│   │   └── investigate/
│   │       └── route.ts          # Server-side investigation API, SSE streaming & CORS enforcement
│   ├── globals.css               # Dark cybersecurity guardian design tokens & styles
│   ├── layout.tsx                # Root layout & security metadata
│   └── page.tsx                  # Web dashboard UI, HUD terminal, Action Preview & Ledger
├── extension/
│   ├── manifest.json             # Chrome Manifest V3 declaration
│   ├── popup.html                # Extension popup markup
│   ├── popup.css                 # Dark cybersecurity popup styles
│   ├── background.js             # Bundled service worker
│   ├── popup.js                  # Bundled popup script
│   ├── content.js                # Bundled content script
│   └── src/
│       ├── api-client.ts         # Extension API client with timeout & error handling
│       ├── background.ts         # Service worker, navigation monitor & storage manager
│       ├── content.ts            # Content script
│       ├── popup.ts              # Popup UI controller & renderer
│       └── types.ts              # Extension TypeScript definitions
├── lib/
│   ├── policy.ts                 # Deterministic 4-outcome policy engine & Action Preview
│   ├── tinyfish.ts               # TinyFish remote browser runner & SSE parser
│   ├── types.ts                  # Shared data models & evidence schemas
│   └── url-safety.ts             # SSRF prevention & destination safety validator
├── tests/
│   ├── api-security.test.ts      # CORS, payload size, SSRF & header security tests
│   ├── extension.test.ts         # Extension settings, ledger & API client tests
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

   # Comma-separated 32-character Chrome Extension IDs approved for CORS
   ALLOWED_EXTENSION_IDS=aheadguardextensiondevid123456
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

## Installing the Chrome Extension

1. Build the extension bundle:
   ```bash
   npm run build:extension
   ```
2. Open Google Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** via the toggle in the top-right corner.
4. Click **Load unpacked**.
5. Select the `extension` folder located inside the project repository.
6. The AheadGuard AI shield icon will appear in your Chrome toolbar. Pin it for quick access.

---

## Running Verification Tests

AheadGuard AI includes a suite of 77 automated tests verifying safety policies, SSE streaming, CORS allowlisting, and 26 real-world security scenarios:

```bash
# Run unit & integration test suite (Vitest)
npm test

# Run ESLint
npm run lint

# Run TypeScript type check
npx tsc --noEmit

# Run Next.js production build
npm run build
```

---

## Development Principles & Responsible Disclosure

AheadGuard AI is a decision-support guardian grounded strictly in verifiable, observable evidence. It does not replace client-side endpoint security, antivirus solutions, or operating system protections. Users must never paste passwords, OTPs, or private personal data into the investigation engine.

---

## License

This project is licensed under the [MIT License](LICENSE).
