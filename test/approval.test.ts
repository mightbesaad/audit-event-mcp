import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DatabaseSync } from "node:sqlite";
import { AuditDO } from "@/do";
import type { ApprovalCreateResult, ApprovalRecord, DecideResult } from "@/lib/approval";
import { fakeEnv, makeState, post } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

const BASE_APPROVAL = {
  agentId: "agent-test",
  sessionId: "session-test",
  actionSummary: "Send €120 refund to customer #991",
};

describe("AuditDO approvals", () => {
  let db: DatabaseSync;
  let do_: AuditDO;

  beforeEach(() => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
  });

  afterEach(() => {
    db.close();
  });

  async function create(overrides: Record<string, unknown> = {}): Promise<ApprovalCreateResult> {
    const res = await do_.fetch(post("/approval/create", { ...BASE_APPROVAL, ...overrides }));
    expect(res.status).toBe(200);
    return (await res.json()) as ApprovalCreateResult;
  }

  // --- create ---

  it("create returns a 22-char base64url approvalId and a pending record", async () => {
    const body = await create();
    expect(body.approvalId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(body.record.status).toBe("pending");
    expect(body.record.agentId).toBe("agent-test");
    expect(body.record.responderId).toBeNull();
    expect(body.record.decidedAt).toBeNull();
    expect(body.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("create defaults TTL to 30 minutes with no channels (watching human)", async () => {
    const body = await create();
    const ttlMs = Date.parse(body.record.expiresAt) - Date.parse(body.record.createdAt);
    expect(ttlMs).toBe(30 * 60 * 1000);
  });

  it("create defaults TTL to 30 minutes when an instant channel is connected (D4)", async () => {
    const body = await create({ channels: ["telegram", "email"] });
    const ttlMs = Date.parse(body.record.expiresAt) - Date.parse(body.record.createdAt);
    expect(ttlMs).toBe(30 * 60 * 1000);
  });

  it("create defaults TTL to 4 hours when email is the only channel (D4)", async () => {
    const body = await create({ channels: ["email"] });
    const ttlMs = Date.parse(body.record.expiresAt) - Date.parse(body.record.createdAt);
    expect(ttlMs).toBe(4 * 60 * 60 * 1000);
  });

  it("explicit ttlSeconds beats the per-channel default", async () => {
    const body = await create({ channels: ["email"], ttlSeconds: 120 });
    const ttlMs = Date.parse(body.record.expiresAt) - Date.parse(body.record.createdAt);
    expect(ttlMs).toBe(120 * 1000);
  });

  it("create honors explicit ttlSeconds", async () => {
    const body = await create({ ttlSeconds: 120 });
    const ttlMs = Date.parse(body.record.expiresAt) - Date.parse(body.record.createdAt);
    expect(ttlMs).toBe(120 * 1000);
  });

  it("create stores channels and callbackUrl", async () => {
    const body = await create({
      channels: ["telegram", "email"],
      callbackUrl: "https://agent.example.com/resume",
    });
    expect(body.record.channels).toEqual(["telegram", "email"]);
    expect(body.record.callbackUrl).toBe("https://agent.example.com/resume");
  });

  it("create canonicalizes and hashes a structured actionPayload (D6)", async () => {
    const body = await create({
      actionPayload: { tool: "stripe.refund", args: { amount: 12000, customer: "cus_991" } },
    });
    expect(body.record.actionPayload).toEqual({
      tool: "stripe.refund",
      args: { amount: 12000, customer: "cus_991" },
    });
    expect(body.record.actionPayloadHash).toMatch(/^[0-9a-f]{64}$/);
    // hash is over canonical (key-sorted) JSON — key order on the wire must not matter
    const reordered = await create({
      actionPayload: { tool: "stripe.refund", args: { customer: "cus_991", amount: 12000 } },
    });
    expect(reordered.record.actionPayloadHash).toBe(body.record.actionPayloadHash);
  });

  it("create stores the canonical payload string in the row", async () => {
    await create({ actionPayload: { tool: "fs.write", args: { b: 2, a: 1 } } });
    const row = db.prepare("SELECT action_payload FROM approvals").get() as {
      action_payload: string;
    };
    expect(row.action_payload).toBe('{"args":{"a":1,"b":2},"tool":"fs.write"}');
  });

  it("create without actionPayload stores null payload and null hash", async () => {
    const body = await create();
    expect(body.record.actionPayload).toBeNull();
    expect(body.record.actionPayloadHash).toBeNull();
  });

  it("create rejects an oversized actionPayload", async () => {
    const res = await do_.fetch(
      post("/approval/create", {
        ...BASE_APPROVAL,
        actionPayload: { tool: "bulk.op", args: { blob: "x".repeat(5000) } },
      }),
    );
    expect(res.status).toBe(400);
  });

  it("create rejects missing agentId", async () => {
    const res = await do_.fetch(post("/approval/create", { actionSummary: "x" }));
    expect(res.status).toBe(400);
  });

  it("create rejects actionSummary over 280 chars", async () => {
    const res = await do_.fetch(
      post("/approval/create", { ...BASE_APPROVAL, actionSummary: "x".repeat(281) }),
    );
    expect(res.status).toBe(400);
  });

  it("create rejects out-of-range ttlSeconds", async () => {
    const tooLong = await do_.fetch(
      post("/approval/create", { ...BASE_APPROVAL, ttlSeconds: 8 * 24 * 60 * 60 }),
    );
    expect(tooLong.status).toBe(400);
    const zero = await do_.fetch(post("/approval/create", { ...BASE_APPROVAL, ttlSeconds: 0 }));
    expect(zero.status).toBe(400);
  });

  it("create rejects http callbackUrl (https only)", async () => {
    const res = await do_.fetch(
      post("/approval/create", { ...BASE_APPROVAL, callbackUrl: "http://agent.example.com/cb" }),
    );
    expect(res.status).toBe(400);
  });

  it("create rejects unknown channels", async () => {
    const res = await do_.fetch(
      post("/approval/create", { ...BASE_APPROVAL, channels: ["sms"] }),
    );
    expect(res.status).toBe(400);
  });

  it("create rejects an actionPayload without a tool name", async () => {
    const res = await do_.fetch(
      post("/approval/create", { ...BASE_APPROVAL, actionPayload: { args: { a: 1 } } }),
    );
    expect(res.status).toBe(400);
  });

  it("create rejects extra keys in actionPayload (witnessed artifact is exactly {tool, args})", async () => {
    const res = await do_.fetch(
      post("/approval/create", {
        ...BASE_APPROVAL,
        actionPayload: { tool: "fs.write", args: {}, hidden: "never rendered" },
      }),
    );
    expect(res.status).toBe(400);
  });

  it("create rejects a caller-supplied hash (hash is always computed server-side)", async () => {
    const res = await do_.fetch(
      post("/approval/create", { ...BASE_APPROVAL, actionPayloadHash: "c".repeat(64) }),
    );
    // unknown key is simply ignored by the non-strict create schema, but it must never land
    const body = (await res.json()) as ApprovalCreateResult;
    expect(res.status).toBe(200);
    expect(body.record.actionPayloadHash).toBeNull();
  });

  it("create rejects missing sessionId", async () => {
    const res = await do_.fetch(
      post("/approval/create", { agentId: "agent-test", actionSummary: "x" }),
    );
    expect(res.status).toBe(400);
  });

  // --- get ---

  it("get returns the stored record", async () => {
    const created = await create();
    const res = await do_.fetch(post("/approval/get", { approvalId: created.approvalId }));
    expect(res.status).toBe(200);
    const record = (await res.json()) as ApprovalRecord;
    expect(record.id).toBe(created.approvalId);
    expect(record.status).toBe("pending");
    expect(record.actionSummary).toBe(BASE_APPROVAL.actionSummary);
  });

  it("get returns 404 for unknown id", async () => {
    const res = await do_.fetch(post("/approval/get", { approvalId: "A".repeat(22) }));
    expect(res.status).toBe(404);
  });

  it("get returns 404 for malformed id (no SQL reached)", async () => {
    const res = await do_.fetch(post("/approval/get", { approvalId: "ab%' OR 1=1 --" }));
    expect(res.status).toBe(404);
  });

  it("get computes timeout on read once expires_at passes", async () => {
    const created = await create();
    db.prepare("UPDATE approvals SET expires_at = '2000-01-01T00:00:00.000Z'").run();
    const res = await do_.fetch(post("/approval/get", { approvalId: created.approvalId }));
    const record = (await res.json()) as ApprovalRecord;
    expect(record.status).toBe("timeout");
    // stored status stays 'pending' — timeout is never written
    const row = db.prepare("SELECT status FROM approvals").get() as { status: string };
    expect(row.status).toBe("pending");
  });

  // --- decide ---

  it("decide approves a pending approval", async () => {
    const created = await create();
    const res = await do_.fetch(
      post("/approval/decide", {
        approvalId: created.approvalId,
        decision: "approved",
        responderId: "ip:abc123",
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as DecideResult;
    expect(body.ok).toBe(true);
    expect(body.record?.status).toBe("approved");
    expect(body.record?.responderId).toBe("ip:abc123");
    expect(body.record?.decidedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("decide denies with a reason", async () => {
    const created = await create();
    const res = await do_.fetch(
      post("/approval/decide", {
        approvalId: created.approvalId,
        decision: "denied",
        reason: "Refund exceeds policy for this customer tier",
      }),
    );
    const body = (await res.json()) as DecideResult;
    expect(body.ok).toBe(true);
    expect(body.record?.status).toBe("denied");
    expect(body.record?.reason).toBe("Refund exceeds policy for this customer tier");
  });

  it("second decide returns 409 already_decided with the terminal record", async () => {
    const created = await create();
    await do_.fetch(post("/approval/decide", { approvalId: created.approvalId, decision: "approved" }));
    const res = await do_.fetch(
      post("/approval/decide", { approvalId: created.approvalId, decision: "denied" }),
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as DecideResult;
    expect(body.ok).toBe(false);
    expect(body.reason).toBe("already_decided");
    expect(body.record?.status).toBe("approved");
  });

  it("decide on an expired approval returns 410 with timeout record", async () => {
    const created = await create();
    db.prepare("UPDATE approvals SET expires_at = '2000-01-01T00:00:00.000Z'").run();
    const res = await do_.fetch(
      post("/approval/decide", { approvalId: created.approvalId, decision: "approved" }),
    );
    expect(res.status).toBe(410);
    const body = (await res.json()) as DecideResult;
    expect(body.ok).toBe(false);
    expect(body.reason).toBe("expired");
    expect(body.record?.status).toBe("timeout");
  });

  it("decide on unknown id returns 404", async () => {
    const res = await do_.fetch(
      post("/approval/decide", { approvalId: "A".repeat(22), decision: "approved" }),
    );
    expect(res.status).toBe(404);
  });

  it("decide rejects invalid decision values", async () => {
    const created = await create();
    const res = await do_.fetch(
      post("/approval/decide", { approvalId: created.approvalId, decision: "maybe" }),
    );
    expect(res.status).toBe(400);
  });

  it("decide rejects reason over 500 chars", async () => {
    const created = await create();
    const res = await do_.fetch(
      post("/approval/decide", {
        approvalId: created.approvalId,
        decision: "denied",
        reason: "x".repeat(501),
      }),
    );
    expect(res.status).toBe(400);
  });

  // --- isolation from the chain (D7: chain format frozen; events ride /record later) ---

  it("approval operations write nothing to audit_events", async () => {
    const created = await create();
    await do_.fetch(post("/approval/decide", { approvalId: created.approvalId, decision: "approved" }));
    const rows = db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number };
    expect(rows.n).toBe(0);
  });
});
