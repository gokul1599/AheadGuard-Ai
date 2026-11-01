export interface QrInspectionReport {
  rawPayload: string;
  scheme: "upi" | "http" | "https" | "custom" | "unknown";
  parsedParams: Record<string, string>;
  payeeVpa?: string;
  payeeName?: string;
  requestedAmount?: number;
  transactionNote?: string;
  isCollectRequest: boolean;
  isUrgentOrSuspicious: boolean;
  warnings: string[];
  safeAction: string;
}

/**
 * Inspects parsed QR code payload string (such as UPI deep links or web URLs).
 */
export function inspectQrPayload(payload: string): QrInspectionReport {
  const clean = payload.trim();
  const warnings: string[] = [];
  const parsedParams: Record<string, string> = {};

  let scheme: QrInspectionReport["scheme"] = "unknown";
  if (clean.toLowerCase().startsWith("upi://pay")) {
    scheme = "upi";
  } else if (clean.toLowerCase().startsWith("https://")) {
    scheme = "https";
  } else if (clean.toLowerCase().startsWith("http://")) {
    scheme = "http";
  } else {
    scheme = "custom";
  }

  let payeeVpa: string | undefined;
  let payeeName: string | undefined;
  let requestedAmount: number | undefined;
  let transactionNote: string | undefined;
  let isCollectRequest = false;

  if (scheme === "upi") {
    try {
      const url = new URL(clean);
      url.searchParams.forEach((val, key) => {
        parsedParams[key] = val;
      });

      payeeVpa = parsedParams["pa"]; // Payee Address (VPA)
      payeeName = parsedParams["pn"]; // Payee Name
      const am = parsedParams["am"]; // Amount
      if (am) requestedAmount = parseFloat(am);
      transactionNote = parsedParams["tn"]; // Transaction note

      // Check for Collect Request / Debit traps masquerading as refunds
      if (
        /refund|cashback|lottery|reward|claim/i.test(transactionNote || "") ||
        /refund|cashback/i.test(payeeName || "")
      ) {
        warnings.push("QR code transaction note claims 'Refund' or 'Reward', but scanning it will DEBIT your account.");
        isCollectRequest = true;
      }

      if (!payeeVpa) {
        warnings.push("Malformed UPI QR code: Missing Payee Address (pa parameter).");
      }
    } catch {
      warnings.push("Failed to parse standard UPI query parameters.");
    }
  } else if (scheme === "http" || scheme === "https") {
    // Web destination QR
    if (scheme === "http") {
      warnings.push("QR leads to an unencrypted plain HTTP destination.");
    }
    if (/bit\.ly|tinyurl|t\.co|cutt\.ly|is\.gd/i.test(clean)) {
      warnings.push("QR encodes a shortened link hiding the true destination target.");
    }
  }

  const isUrgentOrSuspicious = warnings.length > 0;

  return {
    rawPayload: clean,
    scheme,
    parsedParams,
    payeeVpa,
    payeeName,
    requestedAmount,
    transactionNote,
    isCollectRequest,
    isUrgentOrSuspicious,
    warnings,
    safeAction: isCollectRequest
      ? "DO NOT ENTER YOUR UPI PIN. Entering your PIN transfers money OUT of your account; you never enter a PIN to receive money."
      : isUrgentOrSuspicious
      ? "Verify the recipient name and VPA on your bank screen before authorizing payment."
      : "Ensure payee details match your intended merchant before payment confirmation.",
  };
}
