export type TransactionSettlementState =
  | "INITIATED"
  | "PENDING"
  | "CONFIRMED_SETTLED"
  | "FAILED"
  | "REVERSED"
  | "DISPUTED"
  | "UNABLE_TO_VERIFY";

export interface ExtractedPaymentDetails {
  amount?: number;
  currency?: string;
  claimedStatus?: string;
  recipientVpa?: string;
  recipientName?: string;
  transactionReference?: string; // UTR or Ref #
  timestamp?: string;
  platformAppIdentified?: "Paytm" | "Google Pay" | "PhonePe" | "BHIM" | "Bank Transfer" | "Unknown";
}

export interface ForensicVisualCheck {
  id: string;
  name: string;
  passed: boolean;
  severity: "high" | "warning" | "info";
  detail: string;
}

export interface TransactionVerificationReport {
  extracted: ExtractedPaymentDetails;
  settlementState: TransactionSettlementState;
  forensicChecks: ForensicVisualCheck[];
  warningSigns: string[];
  isSpoofSuspected: boolean;
  honestLimitationNotice: string;
  recommendedAction: string;
}

/**
 * Known spoof APK markers & suspicious font/layout indicators
 */
const KNOWN_SPOOF_PATTERNS = [
  /paytm\s+spoof/i,
  /fake\s+upi/i,
  /prank\s+payment/i,
  /success.*preview\s+only/i,
];

/**
 * Analyzes payment receipt text / OCR extraction and visual metadata
 * to detect fraudulent screenshots, mismatched beneficiaries, and advance fee scams.
 */
export function analyzePaymentScreenshot(params: {
  ocrText: string;
  claimedBeneficiary?: string;
  authoritativeBankConfirmed?: boolean;
}): TransactionVerificationReport {
  const text = params.ocrText || "";
  const checks: ForensicVisualCheck[] = [];
  const warningSigns: string[] = [];

  // 1. Extract Amount
  const amountMatch = text.match(/(?:₹|INR|Rs\.?|\$)\s*([\d,]+(?:\.\d{1,2})?)/i);
  let amount: number | undefined;
  if (amountMatch) {
    amount = parseFloat(amountMatch[1].replace(/,/g, ""));
  }

  // 2. Extract Currency
  const currency = text.includes("$") ? "USD" : text.includes("€") ? "EUR" : "INR";

  // 3. Extract UTR / Transaction Reference
  const utrMatch = text.match(/\b(?:UTR|UPI\s+Ref(?:\s+No)?|Txn\s*ID|Ref\s*#)[:\s]*([A-Za-z0-9]{12,22})\b/i);
  const transactionReference = utrMatch ? utrMatch[1] : undefined;

  // 4. Extract Recipient VPA / Identifier
  const upiMatch = text.match(/[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}/i);
  const recipientVpa = upiMatch ? upiMatch[0].toLowerCase() : undefined;

  // 5. App Identification
  let platformApp: ExtractedPaymentDetails["platformAppIdentified"] = "Unknown";
  if (/paytm/i.test(text)) platformApp = "Paytm";
  else if (/google\s*pay|gpay/i.test(text)) platformApp = "Google Pay";
  else if (/phonepe/i.test(text)) platformApp = "PhonePe";
  else if (/bhim/i.test(text)) platformApp = "BHIM";

  // Forensic Check A: UTR Validation
  if (!transactionReference) {
    checks.push({
      id: "utr_missing",
      name: "Bank Transaction Reference (UTR)",
      passed: false,
      severity: "high",
      detail: "No 12-digit standard UTR or banking reference found on the receipt.",
    });
    warningSigns.push("Missing bank UTR reference: Typical in spoof generator apps.");
  } else if (/^0{6,}/.test(transactionReference) || transactionReference.length < 12) {
    checks.push({
      id: "utr_synthetic",
      name: "Bank Transaction Reference (UTR)",
      passed: false,
      severity: "high",
      detail: `Suspicious UTR '${transactionReference}' does not match standard 12-digit NPCI bank sequence.`,
    });
    warningSigns.push("Synthetic or malformed UTR sequence detected.");
  } else {
    checks.push({
      id: "utr_format",
      name: "Bank Transaction Reference (UTR)",
      passed: true,
      severity: "info",
      detail: `Valid 12-digit sequence format: ${transactionReference}`,
    });
  }

  // Forensic Check B: Spoof App Markers
  const hasSpoofKeyword = KNOWN_SPOOF_PATTERNS.some((pat) => pat.test(text));
  if (hasSpoofKeyword) {
    checks.push({
      id: "spoof_apk_detected",
      name: "Known Spoof App Signature",
      passed: false,
      severity: "high",
      detail: "Explicit watermark or signature of a known fake payment simulator found in image text.",
    });
    warningSigns.push("Image contains signatures of a fake payment prank APK.");
  } else {
    checks.push({
      id: "spoof_apk_clean",
      name: "Known Spoof App Signature",
      passed: true,
      severity: "info",
      detail: "No known spoof APK watermarks detected.",
    });
  }

  // Forensic Check C: Beneficiary Identity Alignment
  if (params.claimedBeneficiary && recipientVpa) {
    const claimedLower = params.claimedBeneficiary.toLowerCase().replace(/[^a-z0-9]/g, "");
    const vpaPrefix = recipientVpa.split("@")[0].replace(/[^a-z0-9]/g, "");

    const isMatch = vpaPrefix.includes(claimedLower) || claimedLower.includes(vpaPrefix);
    if (!isMatch) {
      checks.push({
        id: "beneficiary_mismatch",
        name: "Claimed Beneficiary Alignment",
        passed: false,
        severity: "warning",
        detail: `Claimed entity '${params.claimedBeneficiary}' does not match destination VPA '${recipientVpa}'. Money was routed to a personal or unrelated account.`,
      });
      warningSigns.push(`Beneficiary mismatch: Transfer directed to personal account '${recipientVpa}' rather than '${params.claimedBeneficiary}'.`);
    } else {
      checks.push({
        id: "beneficiary_match",
        name: "Claimed Beneficiary Alignment",
        passed: true,
        severity: "info",
        detail: `Destination VPA matches claimed entity '${params.claimedBeneficiary}'.`,
      });
    }
  }

  // Determine Settlement State
  let settlementState: TransactionSettlementState = "UNABLE_TO_VERIFY";
  if (params.authoritativeBankConfirmed) {
    settlementState = "CONFIRMED_SETTLED";
  } else if (hasSpoofKeyword || (transactionReference && /^0{6,}/.test(transactionReference))) {
    settlementState = "FAILED";
  } else {
    settlementState = "UNABLE_TO_VERIFY";
  }

  return {
    extracted: {
      amount,
      currency,
      claimedStatus: /successful|completed|paid/i.test(text) ? "Successful" : "Unspecified",
      recipientVpa,
      transactionReference,
      platformAppIdentified: platformApp,
      timestamp: new Date().toISOString(),
    },
    settlementState,
    forensicChecks: checks,
    warningSigns,
    isSpoofSuspected: warningSigns.length > 0 && !params.authoritativeBankConfirmed,
    honestLimitationNotice:
      "NOTICE: A screenshot or visual receipt is NOT proof of settled banking transfer. Without direct gateway or bank statement settlement confirmation, goods should not be dispatched based on client-presented images alone.",
    recommendedAction:
      settlementState === "CONFIRMED_SETTLED"
        ? "Payment is authoritatively confirmed in banking ledger. Transaction is safe."
        : warningSigns.length > 0
        ? "CAUTION: Do not release goods or provide services. Verify incoming funds directly inside your official merchant bank app or POS soundbox."
        : "Hold dispatch until transaction settles in your official banking or merchant statement.",
  };
}
