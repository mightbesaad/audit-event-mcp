import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditDO } from "@/do";
import { type ChannelDispatch, requestApproval } from "@/lib/approval-flow";
import { kvEmailForClient } from "@/lib/notify";
import { kvChatForClient } from "@/lib/telegram";
import type { Env } from "@/lib/types";
import { fakeEnv, makeMockKV, makeState } from "./harness";

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
        jurisdiction: () => ({
          idFromName,
          get: () => ({
            fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
          }),
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

// --- channel ladder (D4): telegram now, email escalation armed in the DO ---

describe("requestApproval — channel ladder dispatch", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let env: Env;
  let kv: ReturnType<typeof makeMockKV>;
  let telegramStatus: number;
  let telegramCalls: number;

  beforeEach(() => {
    db = new DBSync(":memory:");
    kv = makeMockKV();
    telegramStatus = 200;
    telegramCalls = 0;
    env = {
      AUDIT_DO: {
        idFromName: (name: string) => name,
        get: () => ({
          fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
        }),
        jurisdiction: () => ({
          idFromName: (name: string) => name,
          get: () => ({
            fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
          }),
        }),
      } as unknown as Env["AUDIT_DO"],
      CHANNELS_KV: kv,
      TELEGRAM_BOT_TOKEN: "123456:TEST-TOKEN",
      RESEND_API_KEY: "re_test_key",
      APPROVAL_TOKEN_SECRET: "test-approval-link-secret",
    } as Env;
    // The DO shares the worker env: its alarm path reads the same secrets.
    do_ = new AuditDO(makeState(db), env);
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      if (!String(input).includes("api.telegram.org")) {
        throw new Error(`Unexpected fetch: ${String(input)}`);
      }
      telegramCalls++;
      return new Response(JSON.stringify({ ok: true }), { status: telegramStatus });
    });
  });

  afterEach(() => {
    db.close();
    vi.unstubAllGlobals();
  });

  async function request(input: Record<string, unknown> = {}): Promise<ChannelDispatch> {
    const result = await requestApproval(env, CLIENT_ID, { ...INPUT, ...input });
    expect(result.status).toBe(200);
    return (result.body as { notifications: ChannelDispatch }).notifications;
  }

  function escalationRow(): { due_at: string; email_to: string } | undefined {
    return db.prepare("SELECT due_at, email_to FROM escalations").get() as
      | { due_at: string; email_to: string }
      | undefined;
  }

  it("instant channel delivered → card sent now, email escalation armed at +10 min", async () => {
    await kv.put(kvChatForClient(CLIENT_ID), "777");
    await kv.put(kvEmailForClient(CLIENT_ID), "founder@example.com");
    const before = Date.now();

    const n = await request({ channels: ["telegram", "email"] });
    expect(n).toEqual({ telegram: "sent", email: "scheduled" });
    expect(telegramCalls).toBe(1);

    const row = escalationRow();
    expect(row?.email_to).toBe("founder@example.com");
    const dueIn = Date.parse(row?.due_at ?? "") - before;
    expect(dueIn).toBeGreaterThanOrEqual(10 * 60 * 1000 - 100);
    expect(dueIn).toBeLessThanOrEqual(10 * 60 * 1000 + 5000);
  });

  it("telegram requested but never connected → email fires immediately", async () => {
    await kv.put(kvEmailForClient(CLIENT_ID), "founder@example.com");
    const before = Date.now();

    const n = await request({ channels: ["telegram", "email"] });
    expect(n).toEqual({ telegram: "not_connected", email: "immediate" });
    expect(telegramCalls).toBe(0);
    expect(Date.parse(escalationRow()?.due_at ?? "")).toBeLessThanOrEqual(before + 5000);
  });

  it("a failed telegram send also escalates immediately — failure is not delivery", async () => {
    telegramStatus = 500;
    await kv.put(kvChatForClient(CLIENT_ID), "777");
    await kv.put(kvEmailForClient(CLIENT_ID), "founder@example.com");

    const n = await request({ channels: ["telegram", "email"] });
    expect(n).toEqual({ telegram: "failed", email: "immediate" });
  });

  it("email-only requests get the immediate email and the 4-hour default TTL", async () => {
    await kv.put(kvEmailForClient(CLIENT_ID), "founder@example.com");
    const result = await requestApproval(env, CLIENT_ID, { ...INPUT, channels: ["email"] });
    const body = result.body as { expiresAt: string; notifications: ChannelDispatch };
    expect(body.notifications.email).toBe("immediate");
    expect(Date.parse(body.expiresAt) - Date.now()).toBeGreaterThan(3.9 * 60 * 60 * 1000);
  });

  it("no approver address configured → reported, nothing armed", async () => {
    const n = await request({ channels: ["email"] });
    expect(n.email).toBe("no_address");
    expect(escalationRow()).toBeUndefined();
  });

  it("an approval expiring inside the escalation window never arms a dead email", async () => {
    await kv.put(kvChatForClient(CLIENT_ID), "777");
    await kv.put(kvEmailForClient(CLIENT_ID), "founder@example.com");
    const n = await request({ channels: ["telegram", "email"], ttlSeconds: 300 });
    expect(n).toEqual({ telegram: "sent", email: "expires_first" });
    expect(escalationRow()).toBeUndefined();
  });

  it("missing channel bindings degrade to 'unconfigured' without blocking the approval", async () => {
    env.TELEGRAM_BOT_TOKEN = undefined;
    env.RESEND_API_KEY = undefined;
    const n = await request({ channels: ["telegram", "email"] });
    expect(n).toEqual({ telegram: "unconfigured", email: "unconfigured" });
  });
});
