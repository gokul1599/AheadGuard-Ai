import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  executeTinyFishInvestigation,
  evaluateGoalStatus,
  extractStructuredJson,
  sanitizeErrorMessage,
} from "../lib/tinyfish";
import { assessInvestigation } from "../lib/policy";

describe("TinyFish SSE Client, Parser & Production Completion Resilience", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // Base Tests
  it("Test 5: Rejects execution when TinyFish API key is missing or empty", async () => {
    await expect(
      executeTinyFishInvestigation({
        url: "https://example.com",
        apiKey: "",
      })
    ).rejects.toThrow(/API key is missing/i);

    await expect(
      executeTinyFishInvestigation({
        url: "https://example.com",
        apiKey: "   ",
      })
    ).rejects.toThrow(/API key is missing/i);
  });

  it("Test 6: Handles authentication failure (HTTP 401/403) from TinyFish API", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      text: async () => JSON.stringify({ error: "Invalid API key" }),
    });

    await expect(
      executeTinyFishInvestigation({
        url: "https://example.com",
        apiKey: "invalid_key",
      })
    ).rejects.toThrow(/HTTP 401/i);
  });

  it("Test 7: Handles HTTP/API error (HTTP 500 / 502)", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 502,
      statusText: "Bad Gateway",
      text: async () => "Upstream browser pool unavailable",
    });

    await expect(
      executeTinyFishInvestigation({
        url: "https://example.com",
        apiKey: "valid_key",
      })
    ).rejects.toThrow(/HTTP 502/i);
  });

  it("Test 8: Handles timeout and aborted streams gracefully", async () => {
    const abortController = new AbortController();
    abortController.abort(); // already aborted

    global.fetch = vi.fn().mockImplementation((_url, init) => {
      if (init?.signal?.aborted) {
        return Promise.reject(new Error("The operation was aborted."));
      }
      return Promise.resolve(new Response(""));
    });

    await expect(
      executeTinyFishInvestigation({
        url: "https://example.com",
        apiKey: "valid_key",
        signal: abortController.signal,
      })
    ).rejects.toThrow();
  });

  // Required Regression Scenarios (1 - 10)

  // Scenario 1: JSON data: events with type: STARTED and type: COMPLETE, without an event: header
  it("Scenario 1: Parses data: lines containing type: STARTED and type: COMPLETE without event: headers (Production Wire Format)", async () => {
    const payload = [
      'data: {"type":"STARTED","run_id":"run-prod-001"}',
      "",
      'data: {"type":"STREAMING_URL","streaming_url":"https://stream.tinyfish.io/session/001"}',
      "",
      'data: {"type":"PROGRESS","purpose":"Navigate to example.com for security investigation"}',
      "",
      'data: {"type":"COMPLETE","status":"COMPLETED","result":{"page_title":"Example Domain","observed_final_url":"https://example.com/","visible_purpose":"Documentation placeholder","positive_signals":["HTTPS TLS active"]}}',
      "",
      "",
    ].join("\n");

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(payload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const progressMessages: string[] = [];
    const result = await executeTinyFishInvestigation({
      url: "https://example.com",
      apiKey: "test_key",
      onProgress: (p) => {
        if (p.type === "progress") progressMessages.push(p.message);
      },
    });

    expect(result.success).toBe(true);
    expect(result.goalFailed).toBe(false);
    expect(result.eventsCount).toBe(4);
    expect(result.streamingUrl).toBe("https://stream.tinyfish.io/session/001");
    expect(progressMessages).toContain("Navigate to example.com for security investigation");
    expect(result.structuredResult?.page_title).toBe("Example Domain");
    expect(result.structuredResult?.visible_purpose).toBe("Documentation placeholder");
    expect(result.receivedEventTypes).toContain("COMPLETE");
  });

  // Scenario 2: Conventional event: COMPLETE stream
  it("Scenario 2: Parses conventional event: COMPLETE stream with separate SSE event headers", async () => {
    const payload = [
      "event: STARTED",
      "data: {}",
      "",
      "event: PROGRESS",
      'data: {"message":"Analyzing form controls"}',
      "",
      "event: COMPLETE",
      'data: {"status":"COMPLETED","result":{"page_title":"Conventional Portal","visible_purpose":"Student Portal"}}',
      "",
      "",
    ].join("\n");

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(payload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://portal.edu",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.structuredResult?.page_title).toBe("Conventional Portal");
    expect(result.structuredResult?.visible_purpose).toBe("Student Portal");
  });

  // Scenario 3: Events split across network chunks
  it("Scenario 3: Correctly reassembles and parses SSE packets fragmented across multiple network chunks", async () => {
    const chunk1 = 'data: {"type":"STARTED"}\n\ndata: {"type":"PROG';
    const chunk2 = 'RESS","purpose":"Scanning page scripts"}\n\n';
    const chunk3 = 'data: {"type":"COMPLETE","status":"COMPLETED","result":{"page_title":"Fra';
    const chunk4 = 'gmented Test","visible_purpose":"Verification of chunk reassembly"}}\n\n';

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(chunk1));
        controller.enqueue(encoder.encode(chunk2));
        controller.enqueue(encoder.encode(chunk3));
        controller.enqueue(encoder.encode(chunk4));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://fragmented.test",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.eventsCount).toBe(3);
    expect(result.structuredResult?.page_title).toBe("Fragmented Test");
    expect(result.structuredResult?.visible_purpose).toBe("Verification of chunk reassembly");
  });

  // Scenario 4: CRLF and LF line ending support
  it("Scenario 4: Handles both CRLF (Windows) and LF (Unix) line delimiters identically", async () => {
    const crlfPayload =
      'data: {"type":"STARTED"}\r\n\r\n' +
      'data: {"type":"COMPLETE","status":"COMPLETED","result":{"page_title":"CRLF Tested"}}\r\n\r\n';

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(crlfPayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://crlf.test",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.structuredResult?.page_title).toBe("CRLF Tested");
  });

  // Scenario 5: Final event processed when EOF arrives without trailing blank line
  it("Scenario 5: Processes final packet present in buffer when stream reaches EOF without trailing double-newline", async () => {
    // Note: No trailing newline at the end of the packet before stream close
    const eofPayload = 'data: {"type":"COMPLETE","status":"COMPLETED","result":{"page_title":"EOF Processed"}}';

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(eofPayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://eof.test",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.structuredResult?.page_title).toBe("EOF Processed");
  });

  // Scenario 6: Successful completion containing structured investigation findings feeds policy engine
  it("Scenario 6: Full structured investigation findings extract real fixture data and yield Low Observed Risk", async () => {
    const fixture = {
      type: "COMPLETE",
      status: "COMPLETED",
      result: {
        page_title: "Internet Assigned Numbers Authority",
        observed_final_url: "https://www.iana.org/",
        claimed_organization: "IANA",
        visible_purpose: "Global technical management of DNS root, IP addresses, and protocol parameters.",
        credential_or_payment_request: false,
        download_or_permission_request: false,
        observed_warning_signs: [],
        positive_signals: [
          "HTTPS connection with valid TLS certificate",
          "Official domain with established institutional history",
          "No credential prompts detected",
        ],
        checks_performed: [
          "Inspected DOM hierarchy and metadata",
          "Verified landing page certificate integrity",
          "Confirmed absence of payment inputs",
        ],
        unknowns: [],
        overall_observation: "Authentic institutional reference destination with zero deceptive signals.",
      },
    };

    const payload = `data: ${JSON.stringify(fixture)}\n\n`;

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(payload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const submittedUrl = new URL("https://www.iana.org");
    const result = await executeTinyFishInvestigation({
      url: submittedUrl.toString(),
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.goalFailed).toBe(false);
    expect(result.structuredResult?.claimed_organization).toBe("IANA");
    expect(result.structuredResult?.positive_signals).toHaveLength(3);

    // Feed to deterministic policy engine
    const report = assessInvestigation({
      submittedUrl,
      tinyFishResult: result,
    });

    expect(report.riskOutcome).toBe("Low observed risk");
    expect(report.observedFacts.pageTitle).toBe("Internet Assigned Numbers Authority");
    expect(report.observedFacts.credentialOrPaymentRequest).toBe(false);
    expect(report.evidenceItems.length).toBeGreaterThan(0);
    expect(report.checksPerformed.some((c) => c.name.includes("Browser:"))).toBe(true);
  });

  // Scenario 7: Terminal failure or cancellation handled as unsuccessful
  it("Scenario 7: Terminal failure and cancellation statuses result in goalFailed and Unknown risk verdict", async () => {
    const failurePayload = [
      'data: {"type":"STARTED"}',
      "",
      'data: {"type":"COMPLETE","status":"FAILED","error":"Navigation timed out: remote host took longer than 30s to respond"}',
      "",
      "",
    ].join("\n");

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(failurePayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const submittedUrl = new URL("https://timeout-host.example");
    const result = await executeTinyFishInvestigation({
      url: submittedUrl.toString(),
      apiKey: "test_key",
    });

    expect(result.success).toBe(false);
    expect(result.goalFailed).toBe(true);
    expect(result.errorMessage).toMatch(/Navigation timed out/i);

    const report = assessInvestigation({
      submittedUrl,
      tinyFishResult: result,
    });

    // Incomplete or failed investigation MUST yield Unknown, NEVER Low Observed Risk
    expect(report.riskOutcome).toBe("Unknown");
    expect(report.threatLikelihood).toBe("Uncertain");
    expect(report.outcomeReason).toMatch(/could not be completed/i);
  });

  it("Scenario 7b: Explicit CANCELLED event is handled as terminal failure with Unknown verdict", async () => {
    const cancelPayload = 'data: {"type":"CANCELLED","error":"Run cancelled by user request"}\n\n';

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(cancelPayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://cancelled.example",
      apiKey: "test_key",
    });

    expect(result.success).toBe(false);
    expect(result.goalFailed).toBe(true);
    expect(result.errorMessage).toMatch(/cancelled/i);

    const report = assessInvestigation({
      submittedUrl: new URL("https://cancelled.example"),
      tinyFishResult: result,
    });
    expect(report.riskOutcome).toBe("Unknown");
  });

  // Scenario 8: Stream ending without a terminal event records diagnostics
  it("Scenario 8: Stream closing without a terminal event records received types and forces Unknown verdict", async () => {
    const truncatedPayload = [
      'data: {"type":"STARTED"}',
      "",
      'data: {"type":"PROGRESS","purpose":"Fetching DNS records"}',
      "",
      'data: {"type":"HEARTBEAT"}',
      "",
      "",
    ].join("\n");

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(truncatedPayload));
        controller.close(); // Closed prematurely
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://interrupted.example",
      apiKey: "test_key",
    });

    expect(result.success).toBe(false);
    expect(result.goalFailed).toBe(true);
    expect(result.errorMessage).toMatch(/without a terminal COMPLETE event/i);
    expect(result.errorMessage).toMatch(/STARTED, PROGRESS, HEARTBEAT/i);
    expect(result.errorMessage).toMatch(/EOF/i);
    expect(result.receivedEventTypes).toEqual(["STARTED", "PROGRESS", "HEARTBEAT"]);

    const report = assessInvestigation({
      submittedUrl: new URL("https://interrupted.example"),
      tinyFishResult: result,
    });

    expect(report.riskOutcome).toBe("Unknown");
    expect(report.threatLikelihood).toBe("Uncertain");
    expect(report.outcomeReason).toMatch(/could not be completed/i);
  });

  // Scenario 9: Invalid JSON payload tolerated without crashing
  it("Scenario 9: Tolerates malformed JSON payloads without crashing and recovers on valid subsequent events", async () => {
    const payload = [
      "data: {this is broken json not closed",
      "",
      'data: {"type":"PROGRESS","purpose":"Recovered from bad packet"}',
      "",
      'data: {"type":"COMPLETE","status":"COMPLETED","result":{"page_title":"Resilient Domain"}}',
      "",
      "",
    ].join("\n");

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(payload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://malformed-json.example",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.structuredResult?.page_title).toBe("Resilient Domain");
  });

  // Scenario 10: Completed stream with missing or malformed result data
  it("Scenario 10: Completed event with null or empty result is flagged as goalFailed and yields Unknown", async () => {
    const emptyResultPayload = 'data: {"type":"COMPLETE","status":"COMPLETED","result":{}}\n\n';

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(emptyResultPayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://empty-result.example",
      apiKey: "test_key",
    });

    expect(result.success).toBe(false);
    expect(result.goalFailed).toBe(true);
    expect(result.errorMessage).toMatch(/empty or malformed result data/i);

    const report = assessInvestigation({
      submittedUrl: new URL("https://empty-result.example"),
      tinyFishResult: result,
    });

    expect(report.riskOutcome).toBe("Unknown");
    expect(report.riskOutcome).not.toBe("Low observed risk");
  });

  // Helper Sanitization Tests
  it("Security: sanitizeErrorMessage strips sensitive API keys and authorization tokens", () => {
    const rawMsg = "Failed connecting with sk-tinyfish-4sfpK_YhoBdUQ04xEwhTKcpD6k-YAlyK using Bearer eyJhbGciOi";
    const cleaned = sanitizeErrorMessage(rawMsg, "sk-tinyfish-4sfpK_YhoBdUQ04xEwhTKcpD6k-YAlyK");

    expect(cleaned).not.toContain("sk-tinyfish-4sfpK_YhoBdUQ04xEwhTKcpD6k-YAlyK");
    expect(cleaned).toContain("[REDACTED_API_KEY]");
  });

  it("extractStructuredJson extracts JSON from direct object, markdown fence, or braces", () => {
    // 1. Direct JSON
    const direct = extractStructuredJson('{"page_title":"Direct"}');
    expect(direct?.page_title).toBe("Direct");

    // 2. Markdown fence
    const fenced = extractStructuredJson('Here is the report:\n```json\n{"page_title":"Fenced"}\n```\nDone.');
    expect(fenced?.page_title).toBe("Fenced");

    // 3. Braces slice
    const braced = extractStructuredJson('Leading text {"page_title":"Braced"} trailing text');
    expect(braced?.page_title).toBe("Braced");

    // 4. Invalid
    expect(extractStructuredJson("no json here")).toBeNull();
  });

  it("evaluateGoalStatus evaluates null, malformed, or empty results as goalFailed", () => {
    const resNull = evaluateGoalStatus(null);
    expect(resNull.goalFailed).toBe(true);
    expect(resNull.errorMessage).toMatch(/empty or non-object/i);

    const resEmpty = evaluateGoalStatus({});
    expect(resEmpty.goalFailed).toBe(true);
    expect(resEmpty.errorMessage).toMatch(/empty or malformed result data/i);
  });
});
