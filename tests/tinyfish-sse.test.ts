import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  executeTinyFishInvestigation,
  evaluateGoalStatus,
} from "../lib/tinyfish";

describe("TinyFish SSE Client & Parser (Tests 5 - 13)", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

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

  it("Test 9: Correctly parses SSE messages split across arbitrary network chunks", async () => {
    // Simulate stream split mid-event and mid-JSON payload across 4 chunks
    const chunk1 = 'event: PROGRESS\ndata: {"message": "Load';
    const chunk2 = 'ing page elements..."}\n\n';
    const chunk3 = 'event: COMPLETE\ndata: {"status": "COMPLETED", "result": ';
    const chunk4 = '{"page_title": "Example Domain", "visible_purpose": "Test"}}\n\n';

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

    const progressMessages: string[] = [];
    const result = await executeTinyFishInvestigation({
      url: "https://example.com",
      apiKey: "test_key",
      onProgress: (p) => {
        if (p.type === "progress") progressMessages.push(p.message);
      },
    });

    expect(result.eventsCount).toBeGreaterThanOrEqual(2);
    expect(progressMessages).toContain("Loading page elements...");
    expect(result.completeData).toBeDefined();
    expect(result.goalFailed).toBe(false);
    expect(result.structuredResult?.page_title).toBe("Example Domain");
  });

  it("Test 10: Successful COMPLETE event with a valid result parses correctly", async () => {
    const completeJson = {
      status: "COMPLETED",
      result: {
        page_title: "Official College Portal",
        observed_final_url: "https://college.edu/portal",
        claimed_organization: "State College",
        visible_purpose: "Student sign-in",
        credential_or_payment_request: true,
        download_or_permission_request: false,
        observed_warning_signs: [],
        positive_signals: ["Valid official domain", "HTTPS transport"],
        checks_performed: ["Verified landing page title", "Inspected login form"],
        unknowns: [],
        overall_observation: "Standard student login portal.",
      },
    };

    const ssePayload = `event: STARTED\ndata: {}\n\nevent: COMPLETE\ndata: ${JSON.stringify(completeJson)}\n\n`;

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(ssePayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://college.edu/portal",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.goalFailed).toBe(false);
    expect(result.structuredResult?.page_title).toBe("Official College Portal");
    expect(result.structuredResult?.claimed_organization).toBe("State College");
  });

  it("Test 11: COMPLETE event with failure status or error information is flagged as goalFailed", async () => {
    const failedJson = {
      status: "FAILED",
      error: "Navigation timeout: Destination server refused connection.",
    };

    const ssePayload = `event: COMPLETE\ndata: ${JSON.stringify(failedJson)}\n\n`;

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(ssePayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://offline-site.com",
      apiKey: "test_key",
    });

    expect(result.goalFailed).toBe(true);
    expect(result.success).toBe(false);
    expect(result.errorMessage).toMatch(/refused connection|failed/i);
  });

  it("Test 12: Incomplete, malformed or empty investigation result handled conservatively", async () => {
    // Stream ends without any valid data
    const ssePayload = `event: STARTED\ndata: {}\n\n`;
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(ssePayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://example.com",
      apiKey: "test_key",
    });

    expect(result.success).toBe(false);
    expect(result.goalFailed).toBe(true);
    expect(result.errorMessage).toMatch(/COMPLETE event/i);

    // Test evaluateGoalStatus directly with malformed input
    const evalResult = evaluateGoalStatus(null);
    expect(evalResult.goalFailed).toBe(true);

    const evalResult2 = evaluateGoalStatus({});
    expect(evalResult2.goalFailed).toBe(false); // empty object without error is evaluated, but no keys
  });

  it("Test 13: Tolerates unknown future event types without crashing", async () => {
    const ssePayload = [
      "event: UNKNOWN_FUTURE_EVENT_2027",
      'data: {"metadata": "extra"}',
      "",
      "event: AGENT_INTERNAL_PING",
      'data: {"ping": true}',
      "",
      "event: COMPLETE",
      'data: {"status": "COMPLETED", "result": {"page_title": "Tolerated"}}',
      "",
      "",
    ].join("\n");

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(ssePayload));
        controller.close();
      },
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: stream,
    });

    const result = await executeTinyFishInvestigation({
      url: "https://example.com",
      apiKey: "test_key",
    });

    expect(result.success).toBe(true);
    expect(result.structuredResult?.page_title).toBe("Tolerated");
  });
});
