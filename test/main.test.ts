import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditDO } from "@/do";
import worker from "@/index";
import type { ApprovalCreateResult } from "@/lib/approval";
import type { Env } from "@/lib/types";
import { deriveWebhookSecret, verifyWebhookSignature } from "@/lib/webhook";
// `cloudflare:workers` is aliased to test/stubs/cloudflare-workers.ts in vitest.config.ts
import main, { ApprovalInternal } from "@/main";
import { fakeEnv, makeState, post } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

describe("main module", () => {
  it("default export is exactly the index worker — public HTTP behavior unchanged", () => {
    expect(main).toBe(worker);
  });
});

describe("ApprovalInternal entrypoint", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let idFromName: ReturnType<typeof vi.fn>;
  let entry: ApprovalInternal;
  let env: Env;
  let waited: Promise<unknown>[];
  let ctx: ExecutionContext;

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
    waited = [];
    ctx = { waitUntil: (p: Promise<unknown>) => waited.push(p) } as unknown as ExecutionContext;
    entry = new ApprovalInternal(ctx, env);
  });

  afterEach(() => {
    db.close();
  });

  async function createInDO(
    overrides: Record<string, unknown> = {},
  ): Promise<ApprovalCreateResult> {
    const res = await do_.fetch(
      post("/approval/create", {
        agentId: "agent-test",
        sessionId: "session-test",
        actionSummary: "Test action",
        ...overrides,
      }),
    );
    return (await res.json()) as ApprovalCreateResult;
  }

  it("getApproval derives the DO name server-side from the clientId", async () => {
    const created = await createInDO();
    const record = await entry.getApproval("client-test", created.approvalId);
    expect(record?.id).toBe(created.approvalId);
    expect(record?.status).toBe("pending");
    expect(idFromName).toHaveBeenCalledWith("audit-do-client-test");
  });

  it("getApproval returns null for unknown approvals", async () => {
    expect(await entry.getApproval("client-test", "A".repeat(22))).toBeNull();
  });

  it("getApproval refuses malformed clientId before touching the namespace", async () => {
    const record = await entry.getApproval("../escape", "A".repeat(22));
    expect(record).toBeNull();
    expect(idFromName).not.toHaveBeenCalled();
  });

  it("decideApproval decides end-to-end through the real DO", async () => {
    const created = await createInDO();
    const result = await entry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "denied",
      reason: "Not during business hours",
      responderId: "ip:abc123",
    });
    expect(result.ok).toBe(true);
    expect(result.record?.status).toBe("denied");
    expect(result.record?.reason).toBe("Not during business hours");
    const row = db.prepare("SELECT status, reason FROM approvals").get() as {
      status: string;
      reason: string;
    };
    expect(row.status).toBe("denied");
    expect(row.reason).toBe("Not during business hours");
  });

  it("decideApproval refuses malformed ids as not_found without touching the namespace", async () => {
    const result = await entry.decideApproval({
      clientId: "bad/../client",
      approvalId: "A".repeat(22),
      decision: "approved",
    });
    expect(result).toEqual({ ok: false, reason: "not_found" });
    expect(idFromName).not.toHaveBeenCalled();
  });

  it("decideApproval surfaces already_decided from the DO", async () => {
    const created = await createInDO();
    const base = {
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "approved" as const,
    };
    await entry.decideApproval(base);
    const second = await entry.decideApproval({ ...base, decision: "denied" });
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("already_decided");
    expect(second.record?.status).toBe("approved");
  });

  it("decideApproval witnesses the decision as approval.decided in the approval's session", async () => {
    const created = await createInDO();
    await entry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "denied",
      reason: "Not during business hours",
      responderId: "ip:abc123",
    });
    const row = db
      .prepare("SELECT event_type, agent_id, session_id, input_hash FROM audit_events")
      .get() as {
      event_type: string;
      agent_id: string;
      session_id: string;
      input_hash: string | null;
    };
    expect(row.event_type).toBe("approval.decided");
    expect(row.agent_id).toBe("agent-test");
    expect(row.session_id).toBe("session-test");
    expect(row.input_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("decideApproval witnesses nothing when the decide fails", async () => {
    const created = await createInDO();
    await entry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "approved",
    });
    // second decide: already_decided → no second chain event
    await entry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "denied",
    });
    const rows = db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number };
    expect(rows.n).toBe(1);
  });

  it("POSTs the signed decision webhook via waitUntil when callbackUrl is set", async () => {
    const created = await createInDO({ callbackUrl: "https://agent.example.com/resume" });
    let captured: { url: string; init: RequestInit } | null = null;
    vi.stubGlobal("fetch", async (url: RequestInfo | URL, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      return new Response("ok");
    });
    const signingEntry = new ApprovalInternal(ctx, {
      ...env,
      WEBHOOK_SIGNING_SECRET: "master-test",
    });

    const result = await signingEntry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "approved",
      responderId: "ip:abc123",
    });
    expect(result.ok).toBe(true);
    await Promise.all(waited);
    vi.unstubAllGlobals();

    expect(captured).not.toBeNull();
    const { url, init } = captured as unknown as { url: string; init: RequestInit };
    expect(url).toBe("https://agent.example.com/resume");
    const raw = init.body as string;
    const body = JSON.parse(raw) as {
      type: string;
      approval: { id: string; status: string; sessionId: string };
      chainEvent: { id: string; chainHash: string } | null;
    };
    expect(body.type).toBe("approval.decided");
    expect(body.approval.id).toBe(created.approvalId);
    expect(body.approval.status).toBe("approved");
    expect(body.approval.sessionId).toBe("session-test");

    // the webhook carries the chain pointer of the freshly witnessed decided event
    const eventRow = db
      .prepare("SELECT id, chain_hash FROM audit_events WHERE event_type = 'approval.decided'")
      .get() as { id: string; chain_hash: string };
    expect(body.chainEvent).toEqual({ id: eventRow.id, chainHash: eventRow.chain_hash });

    const secret = await deriveWebhookSecret("master-test", "client-test");
    const headers = init.headers as Record<string, string>;
    expect(
      await verifyWebhookSignature(secret, headers["X-Kajaril-Signature"] as string, raw),
    ).toBe(true);
  });

  it("sends no webhook when WEBHOOK_SIGNING_SECRET is unset (fail closed, still witnesses)", async () => {
    const created = await createInDO({ callbackUrl: "https://agent.example.com/resume" });
    const fetchSpy = vi.fn(async () => new Response("ok"));
    vi.stubGlobal("fetch", fetchSpy);
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    const result = await entry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "approved",
    });
    expect(result.ok).toBe(true);
    await Promise.all(waited);
    vi.unstubAllGlobals();

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(consoleError).toHaveBeenCalled();
    consoleError.mockRestore();
    const rows = db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number };
    expect(rows.n).toBe(1);
  });

  it("sends no webhook when the approval has no callbackUrl", async () => {
    const created = await createInDO();
    const fetchSpy = vi.fn(async () => new Response("ok"));
    vi.stubGlobal("fetch", fetchSpy);
    const signingEntry = new ApprovalInternal(ctx, {
      ...env,
      WEBHOOK_SIGNING_SECRET: "master-test",
    });
    await signingEntry.decideApproval({
      clientId: "client-test",
      approvalId: created.approvalId,
      decision: "approved",
    });
    await Promise.all(waited);
    vi.unstubAllGlobals();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
