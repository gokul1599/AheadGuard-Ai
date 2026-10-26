export interface UrlValidationSuccess {
  valid: true;
  url: URL;
  normalizedUrl: string;
  hasPunycode: boolean;
  isNumericIp: boolean;
  isHttp: boolean;
}

export interface UrlValidationFailure {
  valid: false;
  error: string;
}

export type UrlValidationResult = UrlValidationSuccess | UrlValidationFailure;

/**
 * Extracts a candidate URL from free-form user text or returns null.
 */
export function extractUrlFromText(input: string): string | null {
  if (!input || typeof input !== "string") return null;
  // Match http or https URLs, trimming surrounding punctuation
  const candidate = input.match(/https?:\/\/[^\s<>"'`)]+/i)?.[0];
  if (!candidate) return null;
  return candidate.replace(/[),.;!?]+$/, "");
}

/**
 * Checks if an IPv4 octet string uses octal notation (e.g. "0177") or hex ("0x7f").
 */
function isAlternateEncoding(part: string): boolean {
  if (part.startsWith("0x") || part.startsWith("0X")) return true;
  if (part.length > 1 && part.startsWith("0") && /^\d+$/.test(part)) return true;
  return false;
}

/**
 * Checks whether an IP integer is in a reserved or private range.
 */
function isPrivateOrReservedIpv4(a: number, b: number, c: number, d: number): boolean {
  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 10.0.0.0/8 (Private)
  if (a === 10) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local & AWS/Azure/GCP cloud metadata)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (Private: 172.16.0.0 – 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;
  // 100.64.0.0/10 (Carrier-grade NAT: 100.64.0.0 - 100.127.255.255)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  // 224.0.0.0/4 (Multicast: 224-239)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 (Reserved / Future use: 240-255)
  if (a >= 240) return true;
  // 255.255.255.255 (Broadcast)
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  return false;
}

/**
 * Evaluates whether a destination hostname or IP literal is unsafe (private, loopback, metadata).
 */
export function isUnsafeDestination(hostname: string): { unsafe: boolean; reason?: string } {
  const host = hostname.toLowerCase().trim().replace(/^\[|\]$/g, "");

  // Hostname aliases for local / cloud metadata
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan") ||
    host === "metadata.google.internal" ||
    host === "instance-data"
  ) {
    return { unsafe: true, reason: "Local, internal, or cloud-metadata destinations cannot be investigated." };
  }

  // IPv6 checks
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") {
    return { unsafe: true, reason: "IPv6 loopback destination is not permitted." };
  }
  if (host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) {
    return { unsafe: true, reason: "IPv6 link-local and unique-local destinations are not permitted." };
  }
  // IPv4-mapped IPv6: ::ffff:127.0.0.1 or ::ffff:7f00:1
  if (host.startsWith("::ffff:") || host.startsWith("0:0:0:0:0:ffff:")) {
    const remainder = host.replace(/^(?:0:0:0:0:0:)?::?ffff:/, "");
    if (remainder.includes(".")) {
      const v4Check = isUnsafeDestination(remainder);
      if (v4Check.unsafe) return v4Check;
    }
    const hexWords = remainder.split(":");
    if (hexWords.length === 2) {
      const high = parseInt(hexWords[0], 16);
      const low = parseInt(hexWords[1], 16);
      if (!Number.isNaN(high) && !Number.isNaN(low)) {
        const a = (high >> 8) & 255;
        const b = high & 255;
        const c = (low >> 8) & 255;
        const d = low & 255;
        if (isPrivateOrReservedIpv4(a, b, c, d)) {
          return { unsafe: true, reason: "IPv4-mapped IPv6 destination maps to a private/reserved network." };
        }
      }
    }
  }

  // Pure integer / dword IP bypass (e.g., 2130706433 = 127.0.0.1)
  if (/^\d{8,10}$/.test(host)) {
    const num = Number(host);
    if (!Number.isNaN(num) && num >= 0 && num <= 4294967295) {
      const a = (num >>> 24) & 255;
      const b = (num >>> 16) & 255;
      const c = (num >>> 8) & 255;
      const d = num & 255;
      if (isPrivateOrReservedIpv4(a, b, c, d)) {
        return { unsafe: true, reason: "Dword integer IP destination maps to a private/reserved network." };
      }
    }
  }

  // Hexadecimal single integer IP (e.g. 0x7f000001)
  if (/^0x[0-9a-f]{1,8}$/i.test(host)) {
    const num = parseInt(host, 16);
    if (!Number.isNaN(num)) {
      const a = (num >>> 24) & 255;
      const b = (num >>> 16) & 255;
      const c = (num >>> 8) & 255;
      const d = num & 255;
      if (isPrivateOrReservedIpv4(a, b, c, d)) {
        return { unsafe: true, reason: "Hexadecimal IP destination maps to a private/reserved network." };
      }
    }
  }

  // Dotted decimal or octal/hex parts
  const rawParts = host.split(".");
  if (rawParts.length === 4) {
    const hasAlternate = rawParts.some(isAlternateEncoding);
    if (hasAlternate) {
      // Decode alternate octal/hex components
      const parsed = rawParts.map((p) => {
        if (p.startsWith("0x") || p.startsWith("0X")) return parseInt(p, 16);
        if (p.length > 1 && p.startsWith("0")) return parseInt(p, 8);
        return parseInt(p, 10);
      });
      if (parsed.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
        const [a, b, c, d] = parsed;
        if (isPrivateOrReservedIpv4(a, b, c, d)) {
          return { unsafe: true, reason: "Alternate encoded IP maps to a private or reserved network." };
        }
      }
    }

    const parts = rawParts.map(Number);
    if (parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      const [a, b, c, d] = parts;
      if (isPrivateOrReservedIpv4(a, b, c, d)) {
        return { unsafe: true, reason: "Private, local-loopback, or cloud-metadata IP destinations cannot be investigated." };
      }
    }
  }

  return { unsafe: false };
}

/**
 * Performs end-to-end validation and normalization on user input.
 */
export function validateAndNormalizeUrl(rawInput: string): UrlValidationResult {
  if (typeof rawInput === "string") {
    const trimmed = rawInput.trim();
    const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
    if (schemeMatch) {
      const scheme = schemeMatch[1].toLowerCase();
      if (scheme !== "http" && scheme !== "https") {
        return { valid: false, error: `Unsupported protocol (${scheme}:). Only HTTP and HTTPS destinations are supported.` };
      }
    }
  }

  const candidate = extractUrlFromText(rawInput);
  if (!candidate) {
    return { valid: false, error: "No http:// or https:// URL found. Please paste a valid URL or message containing one." };
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: "The provided link is malformed or invalid." };
  }

  // Scheme validation: strictly http or https
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, error: `Unsupported protocol (${parsed.protocol}). Only HTTP and HTTPS destinations are supported.` };
  }

  // Reject embedded credentials (phishing vector: http://user:pass@evil.com)
  if (parsed.username || parsed.password) {
    return { valid: false, error: "URLs containing embedded usernames or passwords are not permitted." };
  }

  // Hostname validation
  const host = parsed.hostname;
  if (!host || host.length > 253) {
    return { valid: false, error: "The destination hostname is invalid or too long." };
  }

  // Port check: allow default or common web ports
  if (parsed.port) {
    const portNum = Number(parsed.port);
    const allowedPorts = [80, 443, 8080, 8443, 3000, 5000];
    if (Number.isNaN(portNum) || portNum < 1 || portNum > 65535 || !allowedPorts.includes(portNum)) {
      return { valid: false, error: `Port ${parsed.port} is not supported. Use standard web ports (80, 443).` };
    }
  }

  // Unsafe destination check
  const safetyCheck = isUnsafeDestination(host);
  if (safetyCheck.unsafe) {
    return { valid: false, error: safetyCheck.reason ?? "This destination cannot be investigated for security reasons." };
  }

  const hasPunycode = host.includes("xn--");
  const isNumericIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
  const isHttp = parsed.protocol === "http:";

  return {
    valid: true,
    url: parsed,
    normalizedUrl: parsed.toString(),
    hasPunycode,
    isNumericIp,
    isHttp,
  };
}
