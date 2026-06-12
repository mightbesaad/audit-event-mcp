import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditDO } from "@/do";
import type { ApprovalCreateResult } from "@/lib/approval";
import { EMAIL_FROM, EMAIL_REPLY_TO } from "@/lib/notify";
import type { Env } from "@/lib/types";
import { makeState, post } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

// Email-fallback escalations (D4): armed by the flow layer, fired by the DO's alarm.
// All Resend traffic here is a stubbed fetch — no real email leaves the suite.

const CLIENT_ID = "client-test";
const EMAIL_TO = "founder@example.com";
const LINK_SECRET = "test-approval-link-secret";

interface ResendCall {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

function stubResendFetch(status = 200): ResendCall[] {
  const calls: ResendCall[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (!url.includes("api.resend.com")) throw new Error(`Unexpected fetch: ${url}`);
    calls.push({
      url,
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: JSON.parse(String(init?.body)) as Record<string, unknown>,
    });
    return status === 200 ? Response.json({ id: "email-1" }) : new Response("boom", { status });
  });
  return calls;
}

describe("escalations — arm + alarm", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let alarms: { current: number | null };

  beforeEach(() => {
    db = new DBSync(":memory:");
    alarms = { current: null };
    do_ = new AuditDO(makeState(db, alarms), {
      RESEND_API_KEY: "re_test_key",
      APPROVAL_TOKEN_SECRET: LINK_SECRET,
    } as Env);
  });

  afterEach(() => {
    db.close();
    vi.unstubAllGlobals();
  });

  async function createApproval(ttlSeconds = 1800): Promise<string> {
    const res = await do_.fetch(
      post("/approval/create", {
        agentId: "agent-test",
        sessionId: "session-test",
        actionSummary: "Send €120 refund to customer #991",
        channels: ["telegram", "email"],
        ttlSeconds,
      }),
    );
    expect(res.ok).toBe(true);
    return ((await res.json()) as ApprovalCreateResult).approvalId;
  }

  function arm(approvalId: string, dueAtMs: number, overrides: Record<string, unknown> = {}) {
    return do_.fetch(
      post("/approval/arm-escalation", {
        approvalId,
        clientId: CLIENT_ID,
        emailTo: EMAIL_TO,
        dueAtMs,
        ...overrides,
      }),
    );
  }

  it("arming stores the row and schedules the DO alarm at dueAt", async () => {
    const id = await createApproval();
    const dueAtMs = Date.now() + 600_000;
    const res = await arm(id, dueAtMs);
    expect(res.status).toBe(200);
    expect(alarms.current).toBe(dueAtMs);
    const row = db
      .prepare(
        "SELECT client_id, email_to, due_at, fired_at FROM escalations WHERE approval_id = ?",
      )
      .get(id) as { client_id: string; email_to: string; due_at: string; fired_at: string | null };
    expect(row.client_id).toBe(CLIENT_ID);
    expect(row.email_to).toBe(EMAIL_TO);
    expect(Date.parse(row.due_at)).toBe(dueAtMs);
    expect(row.fired_at).toBeNull();
  });

  it("an earlier existing alarm is never pushed later, a later one is pulled in", async () => {
    const id = await createApproval();
    alarms.current = Date.now() + 60_000;
    await arm(id, Date.now() + 600_000);
    expect(alarms.current).toBeLessThanOrEqual(Date.now() + 60_000);

    alarms.current = Date.now() + 3_600_000;
    const dueAtMs = Date.now() + 600_000;
    await arm(id, dueAtMs);
    expect(alarms.current).toBe(dueAtMs);
  });

  it("refuses malformed input and unknown or decided approvals", async () => {
    const id = await createApproval();
    expect((await arm("../escape", Date.now())).status).toBe(400);
    expect((await arm(id, Date.now(), { clientId: "../escape" })).status).toBe(400);
    expect((await arm(id, Date.now(), { emailTo: "not-an-email" })).status).toBe(400);
    expect((await arm(id, Date.now(), { dueAtMs: "soon" })).status).toBe(400);
    expect((await arm("AbCdEfGhIjKlMnOpQrStUv", Date.now())).status).toBe(404);

    await do_.fetch(post("/approval/decide", { approvalId: id, decision: "approved" }));
    expect((await arm(id, Date.now())).status).toBe(409);
  });

  it("fires a due escalation: Resend is called with the pinned sender identity", async () => {
    const calls = stubResendFetch();
    const id = await createApproval();
    await arm(id, Date.now() - 1);

    await do_.alarm();

    expect(calls).toHaveLength(1);
    const call = calls[0] as ResendCall;
    expect(call.headers.Authorization).toBe("Bearer re_test_key");
    expect(call.body.from).toBe(EMAIL_FROM);
    expect(call.body.reply_to).toBe(EMAIL_REPLY_TO);
    expect(call.body.to).toEqual([EMAIL_TO]);
    expect(String(call.body.subject)).toContain("agent-test");
    // The decide link is minted fresh at fire time, never stored
    expect(String(call.body.text)).toContain("https://go.kajaril.com/a/v1.");

    const row = db
      .prepare("SELECT fired_at, result FROM escalations WHERE approval_id = ?")
      .get(id) as { fired_at: string | null; result: string | null };
    expect(row.fired_at).not.toBeNull();
    expect(row.result).toBe("sent");
  });

  it("an approval decided before the email was due is superseded — nothing is sent", async () => {
    const calls = stubResendFetch();
    const id = await createApproval();
    await arm(id, Date.now() - 1);
    await do_.fetch(post("/approval/decide", { approvalId: id, decision: "approved" }));

    await do_.alarm();

    expect(calls).toHaveLength(0);
    const row = db.prepare("SELECT result FROM escalations WHERE approval_id = ?").get(id) as {
      result: string | null;
    };
    expect(row.result).toBe("superseded");
  });

  it("an expired approval is also superseded", async () => {
    const calls = stubResendFetch();
    const id = await createApproval(1);
    await arm(id, Date.now() - 1);
    await new Promise((r) => setTimeout(r, 1100));

    await do_.alarm();
    expect(calls).toHaveLength(0);
    const row = db.prepare("SELECT result FROM escalations WHERE approval_id = ?").get(id) as {
      result: string | null;
    };
    expect(row.result).toBe("superseded");
  });

  it("without the link secret no email is sent — a decide link is the email's whole job", async () => {
    const calls = stubResendFetch();
    db.close();
    db = new DBSync(":memory:");
    alarms = { current: null };
    do_ = new AuditDO(makeState(db, alarms), { RESEND_API_KEY: "re_test_key" } as Env);
    const id = await createApproval();
    await arm(id, Date.now() - 1);

    await do_.alarm();
    expect(calls).toHaveLength(0);
    const row = db.prepare("SELECT result FROM escalations WHERE approval_id = ?").get(id) as {
      result: string | null;
    };
    expect(row.result).toBe("skipped_no_link");
  });

  it("a Resend failure is recorded and not retried — single attempt like the webhook", async () => {
    const calls = stubResendFetch(500);
    const id = await createApproval();
    await arm(id, Date.now() - 1);

    await do_.alarm();
    expect(calls).toHaveLength(1);
    const row = db
      .prepare("SELECT fired_at, result FROM escalations WHERE approval_id = ?")
      .get(id) as { fired_at: string | null; result: string | null };
    expect(row.fired_at).not.toBeNull();
    expect(row.result).toBe("failed");

    await do_.alarm();
    expect(calls).toHaveLength(1);
  });

  it("after firing, the alarm re-arms for the next future escalation", async () => {
    stubResendFetch();
    const dueNow = await createApproval();
    const dueLater = await createApproval();
    const laterMs = Date.now() + 600_000;
    await arm(dueNow, Date.now() - 1);
    await arm(dueLater, laterMs);

    // The platform consumes an alarm before invoking the handler — getAlarm() is null
    // inside alarm(). Mirror that, or the re-arm would see a stale earlier slot.
    alarms.current = null;
    await do_.alarm();

    const fired = db
      .prepare("SELECT result FROM escalations WHERE approval_id = ?")
      .get(dueNow) as {
      result: string | null;
    };
    expect(fired.result).toBe("sent");
    const pending = db
      .prepare("SELECT fired_at FROM escalations WHERE approval_id = ?")
      .get(dueLater) as { fired_at: string | null };
    expect(pending.fired_at).toBeNull();
    expect(alarms.current).toBe(laterMs);
  });
});
