import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditDO } from "@/do";
import { requestApproval } from "@/lib/approval-flow";
import type { Env } from "@/lib/types";
import { fakeEnv, makeState } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

const CLIENT_ID = "client-test";

const INPUT = {
  agentId: "agent-test",
  sessionId: "session-test",
  actionSummary: "Send €120 refund to customer #991",
  actionPayload: { tool: "stripe.refund", args: { amount: 12000, customer: "cus_991" } },
  channels: ["email"],
  callbackUrl: "https://agent.example.com/resume",
};

describe("requestApproval flow", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let idFromName: ReturnType<typeof vi.fn>;
  let env: Env;

  beforeEach(() => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
    idFromName = vi.fn((name: string) => name);
    env = {
      AUDIT_DO: {
        idFromName,
        get: () => ({
          fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
        }),
      } as unknown as Env["AUDIT_DO"],
    } as Env;
  });

  afterEach(() => {
    db.close();
  });

  it("creates the approval and witnesses it as approval.requested in the same session", async () => {
    const result = await requestApproval(env, CLIENT_ID, INPUT);
    expect(result.status).toBe(200);
    const body = result.body as {
      approvalId: string;
      status: string;
      actionPayloadHash: string | null;
      chainEvent: { id: string; chainHash: string };
    };
    expect(body.status).toBe("pending");
    expect(body.actionPayloadHash).toMatch(/^[0-9a-f]{64}$/);
    expect(idFromName).toHaveBeenCalledWith(`audit-do-${CLIENT_ID}`);

    const approvalRow = db.prepare("SELECT id, session_id FROM approvals").get() as {
      id: string;
      session_id: string;
    };
    expect(approvalRow.id).toBe(body.approvalId);
    expect(approvalRow.session_id).toBe("session-test");

    const eventRow = db
      .prepare("SELECT event_type, agent_id, session_id, input_hash, chain_hash FROM audit_events")
      .get() as {
      event_type: string;
      agent_id: string;
      session_id: string;
      input_hash: string | null;
      chain_hash: string;
    };
    expect(eventRow.event_type).toBe("approval.requested");
    expect(eventRow.agent_id).toBe("agent-test");
    expect(eventRow.session_id).toBe("session-test");
    expect(eventRow.input_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(eventRow.chain_hash).toBe(body.chainEvent.chainHash);
  });

  it("refuses a malformed clientId before touching the namespace", async () => {
    const result = await requestApproval(env, "../escape", INPUT);
    expect(result.status).toBe(400);
    expect(idFromName).not.toHaveBeenCalled();
  });

  it("returns 429 and creates nothing when the rate limiter says no", async () => {
    const limit = vi.fn(async () => ({ success: false }));
    env.APPROVAL_RATE_LIMITER = { limit } as unknown as RateLimit;
    const result = await requestApproval(env, CLIENT_ID, INPUT);
    expect(result.status).toBe(429);
    expect((result.body as { error: string }).error).toBe("rate_limited");
    expect(limit).toHaveBeenCalledWith({ key: `req:${CLIENT_ID}` });
    expect(idFromName).not.toHaveBeenCalled();
    const rows = db.prepare("SELECT COUNT(*) AS n FROM approvals").get() as { n: number };
    expect(rows.n).toBe(0);
  });

  it("proceeds when the rate limiter allows", async () => {
    const limit = vi.fn(async () => ({ success: true }));
    env.APPROVAL_RATE_LIMITER = { limit } as unknown as RateLimit;
    const result = await requestApproval(env, CLIENT_ID, INPUT);
    expect(result.status).toBe(200);
    expect(limit).toHaveBeenCalledOnce();
  });

  it("passes DO validation failures through and witnesses nothing", async () => {
    const result = await requestApproval(env, CLIENT_ID, {
      agentId: "agent-test",
      actionSummary: "no sessionId",
    });
    expect(result.status).toBe(400);
    const events = db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number };
    expect(events.n).toBe(0);
    const approvals = db.prepare("SELECT COUNT(*) AS n FROM approvals").get() as { n: number };
    expect(approvals.n).toBe(0);
  });
});
