import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditDO } from "@/do";
import worker from "@/index";
import { mintAccessToken } from "@/lib/m2m";
import { APPROVAL_LINK_GRACE_SECONDS, verifyApprovalToken } from "@/lib/token";
import type { Env } from "@/lib/types";
import { MCP_TOOL_DEFINITIONS } from "@/mcp/tool-definitions";
import { fakeEnv, makeState, post } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

const SIGNING_SECRET = "test-m2m-signing-secret";
const LINK_SECRET = "test-approval-link-secret";
const CLIENT_ID = "client-test";

const APPROVAL_INPUT = {
  agentId: "agent-test",
  sessionId: "session-test",
  actionSummary: "Send €120 refund to customer #991",
  actionPayload: { tool: "stripe.refund", args: { amount: 12000 } },
};

function mcpCall(token: string, name: string, args: Record<string, unknown> = {}): Request {
  return new Request("https://audit-event.kajaril.com/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
}

describe("MCP dispatch — six tools, Bearer auth, scope enforcement", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let env: Env;
  let agentToken: string;
  let adminToken: string;

  beforeEach(async () => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
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
      M2M_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
      APPROVAL_TOKEN_SECRET: LINK_SECRET,
    } as Env;
    agentToken = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "agent" });
    adminToken = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "admin" });
  });

  afterEach(() => {
    db.close();
  });

  it("tools/list exposes exactly the six tools", async () => {
    const res = await worker.fetch(
      new Request("https://audit-event.kajaril.com/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${agentToken}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { tools: { name: string }[] } };
    expect(body.result.tools.map((t) => t.name)).toEqual([
      "record_event",
      "verify_chain",
      "query_events",
      "export_dossier",
      "request_approval",
      "check_approval",
    ]);
    expect(MCP_TOOL_DEFINITIONS).toHaveLength(6);
  });

  it("an agent token can record events but not read chains, query, or export", async () => {
    const recorded = await worker.fetch(
      mcpCall(agentToken, "record_event", {
        agentId: "agent-test",
        eventType: "tool.call",
        purpose: "dispatch test",
        sessionId: "s",
        input: { x: 1 },
      }),
      env,
      {} as never,
    );
    expect(recorded.status).toBe(200);

    for (const tool of ["verify_chain", "query_events", "export_dossier"]) {
      const res = await worker.fetch(mcpCall(agentToken, tool), env, {} as never);
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: { code: number; message: string } };
      expect(body.error.code).toBe(-32001);
      expect(body.error.message).toContain("admin");
    }
  });

  it("an admin token reaches the read-side tools", async () => {
    await worker.fetch(
      mcpCall(adminToken, "record_event", {
        agentId: "agent-test",
        eventType: "tool.call",
        purpose: "dispatch test",
        sessionId: "s",
        input: { x: 1 },
      }),
      env,
      {} as never,
    );
    const res = await worker.fetch(
      mcpCall(adminToken, "query_events", { sessionId: "s" }),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { events: unknown[] } };
    expect(body.result.events).toHaveLength(1);
  });

  it("unknown tools 404 before the scope gate", async () => {
    const res = await worker.fetch(mcpCall(agentToken, "drop_tables"), env, {} as never);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32601);
  });

  it("the reserved approval.* guard survives for Bearer callers", async () => {
    const res = await worker.fetch(
      mcpCall(agentToken, "record_event", {
        eventType: "approval.decided",
        purpose: "fabricated",
        sessionId: "s",
        input: {},
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toContain("reserved");
  });

  it("a garbage Bearer token gets a uniform 401; unset signing secret gets 503", async () => {
    const res = await worker.fetch(mcpCall("not-a-token", "record_event"), env, {} as never);
    expect(res.status).toBe(401);

    env.M2M_TOKEN_SIGNING_SECRET = undefined;
    const closed = await worker.fetch(mcpCall(agentToken, "record_event"), env, {} as never);
    expect(closed.status).toBe(503);
  });

  it("request_approval mints an approval_url whose token outlives the approval by the grace window", async () => {
    const res = await worker.fetch(
      mcpCall(agentToken, "request_approval", APPROVAL_INPUT),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { approvalId: string; expiresAt: string; approvalUrl: string };
    };
    const { approvalId, expiresAt, approvalUrl } = body.result;
    expect(approvalUrl).toMatch(/^https:\/\/go\.kajaril\.com\/a\//);

    const token = approvalUrl.slice("https://go.kajaril.com/a/".length);
    const payload = await verifyApprovalToken(LINK_SECRET, token);
    expect(payload).not.toBeNull();
    expect(payload?.clientId).toBe(CLIENT_ID);
    expect(payload?.approvalId).toBe(approvalId);
    expect(payload?.exp).toBe(
      Math.floor(Date.parse(expiresAt) / 1000) + APPROVAL_LINK_GRACE_SECONDS,
    );
  });

  it("request_approval returns approvalUrl: null when the link secret is unbound", async () => {
    env.APPROVAL_TOKEN_SECRET = undefined;
    const res = await worker.fetch(
      mcpCall(agentToken, "request_approval", APPROVAL_INPUT),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { approvalUrl: string | null } };
    expect(body.result.approvalUrl).toBeNull();
  });

  it("request_approval then check_approval round-trips pending → approved", async () => {
    const created = await worker.fetch(
      mcpCall(agentToken, "request_approval", APPROVAL_INPUT),
      env,
      {} as never,
    );
    const { approvalId } = ((await created.json()) as { result: { approvalId: string } }).result;

    const pending = await worker.fetch(
      mcpCall(agentToken, "check_approval", { approvalId }),
      env,
      {} as never,
    );
    expect(pending.status).toBe(200);
    const pendingBody = (await pending.json()) as { result: { status: string } };
    expect(pendingBody.result.status).toBe("pending");

    await do_.fetch(
      post("/approval/decide", {
        approvalId,
        decision: "approved",
        reason: "looks right",
        responderId: "kind@example.com",
      }),
    );

    const decided = await worker.fetch(
      mcpCall(agentToken, "check_approval", { approvalId }),
      env,
      {} as never,
    );
    const decidedBody = (await decided.json()) as {
      result: { status: string; reason: string; responderId: string; decidedAt: string };
    };
    expect(decidedBody.result.status).toBe("approved");
    expect(decidedBody.result.reason).toBe("looks right");
    expect(decidedBody.result.responderId).toBe("kind@example.com");
    expect(decidedBody.result.decidedAt).not.toBeNull();
  });

  it("check_approval 404s on unknown and malformed ids, and requires approvalId", async () => {
    const unknown = await worker.fetch(
      mcpCall(agentToken, "check_approval", { approvalId: "doesnotexist" }),
      env,
      {} as never,
    );
    expect(unknown.status).toBe(404);

    const malformed = await worker.fetch(
      mcpCall(agentToken, "check_approval", { approvalId: "../../etc" }),
      env,
      {} as never,
    );
    expect(malformed.status).toBe(404);

    const missing = await worker.fetch(mcpCall(agentToken, "check_approval"), env, {} as never);
    expect(missing.status).toBe(400);
    const body = (await missing.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32602);
  });
});

describe("REST approval surface", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let env: Env;
  let agentToken: string;

  beforeEach(async () => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
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
      M2M_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
      APPROVAL_TOKEN_SECRET: LINK_SECRET,
    } as Env;
    agentToken = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "agent" });
  });

  afterEach(() => {
    db.close();
  });

  function restRequest(path: string, init: RequestInit = {}, token?: string): Request {
    return new Request(`https://audit-event.kajaril.com${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
  }

  it("POST /approvals + GET /approvals/:id mirror the MCP tools", async () => {
    const created = await worker.fetch(
      restRequest("/approvals", { method: "POST", body: JSON.stringify(APPROVAL_INPUT) }, agentToken),
      env,
      {} as never,
    );
    expect(created.status).toBe(200);
    const body = (await created.json()) as {
      approvalId: string;
      status: string;
      approvalUrl: string;
      webhookSecret: string | null;
    };
    expect(body.status).toBe("pending");
    expect(body.approvalUrl).toContain("/a/");

    const checked = await worker.fetch(
      restRequest(`/approvals/${body.approvalId}`, { method: "GET" }, agentToken),
      env,
      {} as never,
    );
    expect(checked.status).toBe(200);
    expect(((await checked.json()) as { status: string }).status).toBe("pending");
  });

  it("requires credentials and rejects invalid tokens", async () => {
    const noAuth = await worker.fetch(
      restRequest("/approvals", { method: "POST", body: JSON.stringify(APPROVAL_INPUT) }),
      env,
      {} as never,
    );
    expect(noAuth.status).toBe(401);

    const badToken = await worker.fetch(
      restRequest("/approvals/some-id", { method: "GET" }, "garbage"),
      env,
      {} as never,
    );
    expect(badToken.status).toBe(401);
  });

  it("passes DO validation errors through (bad input → 400)", async () => {
    const res = await worker.fetch(
      restRequest(
        "/approvals",
        { method: "POST", body: JSON.stringify({ agentId: "a" }) },
        agentToken,
      ),
      env,
      {} as never,
    );
    expect(res.status).toBe(400);
  });
});
