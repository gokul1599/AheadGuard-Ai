import { describe, it, expect } from "vitest";
import { validateAndNormalizeUrl } from "../lib/url-safety";

describe("Input & Network Safety (Tests 1 - 4)", () => {
  it("Test 1: Valid public HTTPS URL passes validation and normalizes correctly", () => {
    const result1 = validateAndNormalizeUrl("https://example.com/login?step=1");
    expect(result1.valid).toBe(true);
    if (result1.valid) {
      expect(result1.url.hostname).toBe("example.com");
      expect(result1.isHttp).toBe(false);
      expect(result1.hasPunycode).toBe(false);
      expect(result1.isNumericIp).toBe(false);
    }

    const messageWithUrl = "Hey check your scholarship offer here: https://www.scaler.com/offer now!";
    const result2 = validateAndNormalizeUrl(messageWithUrl);
    expect(result2.valid).toBe(true);
    if (result2.valid) {
      expect(result2.url.hostname).toBe("www.scaler.com");
    }
  });

  it("Test 2: Malformed URL is cleanly rejected", () => {
    const malformedInputs = [
      "not a url at all",
      "ht!tp://broken",
      "://missing-scheme",
      "",
      "   ",
    ];

    for (const input of malformedInputs) {
      const result = validateAndNormalizeUrl(input);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBeDefined();
        expect(typeof result.error).toBe("string");
      }
    }
  });

  it("Test 3: Unsupported URL schemes are rejected (ftp, file, javascript, data)", () => {
    const unsupported = [
      "ftp://files.example.com/archive.zip",
      "file:///etc/passwd",
      "javascript:alert(document.cookie)",
      "data:text/html,<script>alert(1)</script>",
      "gopher://old.internet.net",
    ];

    for (const input of unsupported) {
      const result = validateAndNormalizeUrl(input);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.toLowerCase()).toMatch(/protocol|http|no http/);
      }
    }
  });

  it("Test 4: Local, private, loopback, and cloud metadata destinations are strictly rejected (SSRF defenses)", () => {
    const unsafeDestinations = [
      "http://localhost:3000",
      "https://test.localhost",
      "http://subdomain.local",
      "http://127.0.0.1",
      "http://127.0.0.2",
      "http://10.0.0.1/admin",
      "http://192.168.1.1/router",
      "http://172.16.0.1/internal",
      "http://172.31.255.255",
      "http://169.254.169.254/latest/meta-data/", // AWS metadata
      "http://metadata.google.internal/computeMetadata/v1/", // GCP metadata
      "http://[::1]/secret", // IPv6 loopback
      "http://[fe80::1]/link-local", // IPv6 link-local
      "http://[fc00::1]/unique-local", // IPv6 unique-local
      "http://[::ffff:127.0.0.1]", // IPv4-mapped IPv6
      "http://0177.0.0.1", // Octal representation of 127.0.0.1
      "http://0x7f000001", // Hex representation of 127.0.0.1
      "http://2130706433", // Dword integer representation of 127.0.0.1
      "http://0", // Integer 0 (0.0.0.0)
      "http://127.1", // 2-part shorthand (127.0.0.1)
      "http://127.0.1", // 3-part shorthand (127.0.0.1)
      "http://10.1", // 2-part private shorthand (10.0.0.1)
      "http://192.168.1", // 3-part private shorthand (192.168.0.1)
      "http://169.254.1", // 3-part link-local shorthand
      "http://admin:secret123@example.com", // Embedded credentials
    ];

    for (const destination of unsafeDestinations) {
      const result = validateAndNormalizeUrl(destination);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBeDefined();
      }
    }
  });

  it("Test 5: Rejects URLs containing sensitive credentials, tokens, or passwords in query params or fragments", () => {
    const sensitiveUrls = [
      "https://example.com/reset-password?token=TEST_SECRET_DO_NOT_LEAK",
      "https://example.com/login?password=MY_SECRET_PASSWORD",
      "https://example.com/api/v1?api_key=sk_live_1234567890abcdef",
      "https://example.com/oauth/callback?code=OAUTH_AUTH_CODE&state=CSRF_STATE_VAL",
      "https://example.com/auth?access_token=eyJhbGciOiJIUzI1NiJ9.test.abc",
      "https://example.com/session?sessionid=SESSION_COOKIE_VALUE",
      "https://example.com/oauth#access_token=FRAGMENT_SECRET_DO_NOT_LEAK",
      "https://example.com/profile?client_secret=TOP_SECRET_HEX_VAL",
      "https://example.com/verify?otp=123456",
    ];

    for (const url of sensitiveUrls) {
      const result = validateAndNormalizeUrl(url);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toMatch(/sensitive|credentials|tokens|passwords|hash fragments/i);
      }
    }
  });

  it("Test 6: Preserves innocent non-sensitive query parameters and normalizes correctly", () => {
    const innocentUrls = [
      "https://example.com/search?keyword=software+engineer&page=2&sort=desc",
      "https://example.com/jobs?country_code=US&zip_code=94105&category=technology",
      "https://example.com/catalog?status_code=active&product_code=A100&limit=50",
    ];

    for (const url of innocentUrls) {
      const result = validateAndNormalizeUrl(url);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.normalizedUrl).toContain("example.com");
      }
    }
  });
});
