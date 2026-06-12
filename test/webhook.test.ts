import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildSignatureHeader,
  type DecisionWebhookBody,
  deriveWebhookSecret,
  sendDecisionWebhook,
  verifyWebhookSignature,
  WEBHOOK_SIGNATURE_HEADER,
} from "@/lib/webhook";

const MASTER = "master-secret-for-tests";

describe("deriveWebhookSecret (D9)", () => {
  it("is deterministic for the same master and tenant", async () => {
    expect(await deriveWebhookSecret(MASTER, "client-a")).toBe(
      await deriveWebhookSecret(MASTER, "client-a"),
    );
  });

  it("differs across tenants — one tenant can never verify another's webhooks", async () => {
    expect(await deriveWebhookSecret(MASTER, "client-a")).not.toBe(
      await deriveWebhookSecret(MASTER, "client-b"),
    );
  });

  it("differs across masters (rotation rotates every tenant)", async () => {
    expect(await deriveWebhookSecret(MASTER, "client-a")).not.toBe(
      await deriveWebhookSecret("rotated-master", "client-a"),
    );
  });

  it("is whsec_ + 43 chars of base64url (32 derived bytes)", async () => {
    expect(await deriveWebhookSecret(MASTER, "client-a")).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
  });

  it("refuses an empty master", async () => {
    await expect(deriveWebhookSecret("", "client-a")).rejects.toThrow();
  });
});

describe("webhook signature", () => {
  const body = '{"hello":"world"}';

  it("sign → verify roundtrip", async () => {
    const secret = await deriveWebhookSecret(MASTER, "client-a");
    const header = await buildSignatureHeader(secret, body);
    expect(header).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(await verifyWebhookSignature(secret, header, body)).toBe(true);
  });

  it("rejects a tampered body", async () => {
    const secret = await deriveWebhookSecret(MASTER, "client-a");
    const header = await buildSignatureHeader(secret, body);
    expect(await verifyWebhookSignature(secret, header, '{"hello":"tampered"}')).toBe(false);
  });

  it("rejects the wrong tenant's secret", async () => {
    const a = await deriveWebhookSecret(MASTER, "client-a");
    const b = await deriveWebhookSecret(MASTER, "client-b");
    const header = await buildSignatureHeader(a, body);
    expect(await verifyWebhookSignature(b, header, body)).toBe(false);
  });

  it("rejects a replay outside the tolerance window", async () => {
    const secret = await deriveWebhookSecret(MASTER, "client-a");
    const signedAt = Date.now();
    const header = await buildSignatureHeader(secret, body, signedAt);
    const sixMinutesLater = signedAt + 6 * 60 * 1000;
    expect(await verifyWebhookSignature(secret, header, body, sixMinutesLater)).toBe(false);
    const withinTolerance = signedAt + 2 * 60 * 1000;
    expect(await verifyWebhookSignature(secret, header, body, withinTolerance)).toBe(true);
  });

  it("rejects malformed headers", async () => {
    const secret = await deriveWebhookSecret(MASTER, "client-a");
    expect(await verifyWebhookSignature(secret, "garbage", body)).toBe(false);
    expect(await verifyWebhookSignature(secret, "t=abc,v1=def", body)).toBe(false);
    expect(await verifyWebhookSignature(secret, "", body)).toBe(false);
  });
});

describe("sendDecisionWebhook", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const webhookBody: DecisionWebhookBody = {
    type: "approval.decided",
    approval: {
      id: "AbCdEfGhIjKlMnOpQrStUv",
      agentId: "agent-test",
      sessionId: "session-test",
      status: "approved",
      reason: null,
      responderId: "ip:abc123",
      actionSummary: "Send €120 refund to customer #991",
      actionPayloadHash: "c".repeat(64),
      createdAt: "2026-06-11T10:00:00.000Z",
      decidedAt: "2026-06-11T10:02:11.000Z",
      expiresAt: "2026-06-11T10:30:00.000Z",
    },
    chainEvent: { id: "01hyz0", chainHash: "d".repeat(64) },
  };

  it("POSTs the signed payload, refuses redirects, and the signature verifies", async () => {
    let captured: { url: string; init: RequestInit } | null = null;
    vi.stubGlobal("fetch", async (url: RequestInfo | URL, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      return new Response("ok");
    });

    await sendDecisionWebhook({
      master: MASTER,
      clientId: "client-test",
      callbackUrl: "https://agent.example.com/resume",
      body: webhookBody,
    });

    expect(captured).not.toBeNull();
    const { url, init } = captured as unknown as { url: string; init: RequestInit };
    expect(url).toBe("https://agent.example.com/resume");
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("error");
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    const raw = init.body as string;
    expect(JSON.parse(raw)).toEqual(webhookBody);
    const secret = await deriveWebhookSecret(MASTER, "client-test");
    expect(
      await verifyWebhookSignature(secret, headers[WEBHOOK_SIGNATURE_HEADER] as string, raw),
    ).toBe(true);
  });

  it("never throws — delivery failure is logged, polling remains the contract", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("connection refused");
    });
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(
      sendDecisionWebhook({
        master: MASTER,
        clientId: "client-test",
        callbackUrl: "https://agent.example.com/resume",
        body: webhookBody,
      }),
    ).resolves.toBeUndefined();
    expect(consoleError).toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it("logs non-2xx responses without throwing", async () => {
    vi.stubGlobal("fetch", async () => new Response("nope", { status: 500 }));
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    await sendDecisionWebhook({
      master: MASTER,
      clientId: "client-test",
      callbackUrl: "https://agent.example.com/resume",
      body: webhookBody,
    });
    expect(consoleError).toHaveBeenCalled();
    consoleError.mockRestore();
  });
});
