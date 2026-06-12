import { describe, expect, it, vi } from "vitest";
import worker from "@/go";
import type {
  ApprovalDecision,
  ApprovalInternalClient,
  ApprovalRecord,
  DecideResult,
} from "@/lib/approval";
import { mintApprovalToken } from "@/lib/token";
import type { GoEnv } from "@/lib/types";

const SECRET = "go-test-secret";
const CLIENT_ID = "client-test";
const APPROVAL_ID = "AbCdEfGhIjKlMnOpQrStUv";

function makeRecord(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    id: APPROVAL_ID,
    agentId: "agent-test",
    sessionId: "session-test",
    actionSummary: "Send €120 refund to customer #991",
    actionPayload: null,
    actionPayloadHash: null,
    status: "pending",
    responderId: null,
    reason: null,
    channels: [],
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    decidedAt: null,
    callbackUrl: null,
    ...overrides,
  };
}

function makeEnv(client: Partial<ApprovalInternalClient> = {}): GoEnv {
  return {
    AUDIT: {
      getApproval: client.getApproval ?? (async () => makeRecord()),
      decideApproval:
        client.decideApproval ??
        (async (params: { decision: ApprovalDecision; reason?: string; responderId?: string }) => ({
          ok: true,
          record: makeRecord({
            status: params.decision,
            reason: params.reason ?? null,
            responderId: params.responderId ?? null,
            decidedAt: new Date().toISOString(),
          }),
        })),
    },
    APPROVAL_TOKEN_SECRET: SECRET,
  };
}

async function token(secret = SECRET, exp = Math.floor(Date.now() / 1000) + 3600): Promise<string> {
  return mintApprovalToken(secret, { clientId: CLIENT_ID, approvalId: APPROVAL_ID, exp });
}

function get(path: string): Request {
  return new Request(`https://go.kajaril.com${path}`);
}

function postForm(path: string, fields: Record<string, string>): Request {
  return new Request(`https://go.kajaril.com${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
  });
}

const ctx = {} as ExecutionContext;

describe("go worker — approve page", () => {
  it("renders the pending page for a valid token", async () => {
    const t = await token();
    const res = await worker.fetch(get(`/a/${t}`), makeEnv(), ctx);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Approve agent action?");
    expect(html).toContain("agent-test");
    expect(html).toContain("Send €120 refund to customer #991");
    expect(html).toContain(`/a/${t}/decide`);
  });

  it("sets the donor security headers and CSP with script-src 'none'", async () => {
    const res = await worker.fetch(get(`/a/${await token()}`), makeEnv(), ctx);
    expect(res.headers.get("Content-Security-Policy")).toContain("script-src 'none'");
    expect(res.headers.get("Content-Security-Policy")).toContain("form-action 'self'");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("emits zero inline JS", async () => {
    const pending = await worker.fetch(get(`/a/${await token()}`), makeEnv(), ctx);
    expect((await pending.text()).toLowerCase()).not.toContain("<script");
    const env = makeEnv({ getApproval: async () => makeRecord({ status: "approved" }) });
    const terminal = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    expect((await terminal.text()).toLowerCase()).not.toContain("<script");
  });

  it("escapes HTML in attacker-influenced fields", async () => {
    const env = makeEnv({
      getApproval: async () =>
        makeRecord({
          agentId: "<img src=x onerror=alert(1)>",
          actionSummary: '<script>alert("xss")</script>',
        }),
    });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    const html = await res.text();
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
  });

  it("shows the action payload hash when present (D6)", async () => {
    const hash = "d".repeat(64);
    const env = makeEnv({ getApproval: async () => makeRecord({ actionPayloadHash: hash }) });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    expect(await res.text()).toContain(hash);
  });

  it("shows the structured payload — tool and args — alongside the summary (D6)", async () => {
    const env = makeEnv({
      getApproval: async () =>
        makeRecord({
          actionPayload: { tool: "stripe.refund", args: { amount: 12000, customer: "cus_991" } },
          actionPayloadHash: "d".repeat(64),
        }),
    });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    const html = await res.text();
    expect(html).toContain("stripe.refund");
    expect(html).toContain("cus_991");
    expect(html).toContain("Send €120 refund to customer #991");
  });

  it("escapes HTML inside payload args", async () => {
    const env = makeEnv({
      getApproval: async () =>
        makeRecord({
          actionPayload: { tool: "<script>alert(1)</script>", args: { x: "<img src=x>" } },
        }),
    });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    const html = await res.text();
    expect(html.toLowerCase()).not.toContain("<script");
    expect(html).not.toContain("<img src=x");
  });

  it("returns 404 not-found page for a garbage token without calling the binding", async () => {
    const getApproval = vi.fn(async () => makeRecord());
    const res = await worker.fetch(get("/a/not-a-real-token"), makeEnv({ getApproval }), ctx);
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("invalid or has expired");
    expect(getApproval).not.toHaveBeenCalled();
  });

  it("returns 404 for a token signed with a different secret", async () => {
    const getApproval = vi.fn(async () => makeRecord());
    const foreign = await token("some-other-secret");
    const res = await worker.fetch(get(`/a/${foreign}`), makeEnv({ getApproval }), ctx);
    expect(res.status).toBe(404);
    expect(getApproval).not.toHaveBeenCalled();
  });

  it("returns 404 for an expired token", async () => {
    const expired = await token(SECRET, Math.floor(Date.now() / 1000) - 60);
    const res = await worker.fetch(get(`/a/${expired}`), makeEnv(), ctx);
    expect(res.status).toBe(404);
  });

  it("returns 404 when the approval does not exist in the tenant DO", async () => {
    const env = makeEnv({ getApproval: async () => null });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    expect(res.status).toBe(404);
  });

  it("renders the terminal page for decided approvals", async () => {
    const env = makeEnv({
      getApproval: async () =>
        makeRecord({
          status: "denied",
          reason: "Exceeds refund policy",
          decidedAt: new Date().toISOString(),
        }),
    });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    const html = await res.text();
    expect(html).toContain("Denied");
    expect(html).toContain("Exceeds refund policy");
  });

  it("renders timeout state", async () => {
    const env = makeEnv({ getApproval: async () => makeRecord({ status: "timeout" }) });
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    expect(await res.text()).toContain("Expired before decision");
  });

  it("fails closed with 503 when APPROVAL_TOKEN_SECRET is unset", async () => {
    // built without the key — makeEnv's default parameter would resurrect it on explicit undefined
    const env: GoEnv = { AUDIT: makeEnv().AUDIT };
    const res = await worker.fetch(get(`/a/${await token()}`), env, ctx);
    expect(res.status).toBe(503);
    const decide = await worker.fetch(
      postForm(`/a/${await token()}/decide`, { decision: "approved" }),
      env,
      ctx,
    );
    expect(decide.status).toBe(503);
  });
});

describe("go worker — decide", () => {
  it("routes the decision through the token's tenant, never anything user-supplied", async () => {
    const decideApproval = vi.fn(
      async (_params: {
        clientId: string;
        approvalId: string;
        decision: ApprovalDecision;
      }): Promise<DecideResult> => ({ ok: true, record: makeRecord({ status: "approved" }) }),
    );
    const t = await token();
    const res = await worker.fetch(
      postForm(`/a/${t}/decide`, { decision: "approved", clientId: "attacker-tenant" }),
      makeEnv({ decideApproval }),
      ctx,
    );
    expect(res.status).toBe(200);
    expect(decideApproval).toHaveBeenCalledOnce();
    const args = decideApproval.mock.calls[0]?.[0];
    expect(args?.clientId).toBe(CLIENT_ID);
    expect(args?.approvalId).toBe(APPROVAL_ID);
    expect(args?.decision).toBe("approved");
  });

  it("passes the deny reason through and renders it", async () => {
    const res = await worker.fetch(
      postForm(`/a/${await token()}/decide`, {
        decision: "denied",
        reason: "Customer already refunded last week",
      }),
      makeEnv(),
      ctx,
    );
    const html = await res.text();
    expect(html).toContain("Denied");
    expect(html).toContain("Customer already refunded last week");
  });

  it("rejects decisions other than approved/denied with 400", async () => {
    const res = await worker.fetch(
      postForm(`/a/${await token()}/decide`, { decision: "maybe" }),
      makeEnv(),
      ctx,
    );
    expect(res.status).toBe(400);
  });

  it("renders the prior terminal state on already_decided", async () => {
    const env = makeEnv({
      decideApproval: async () => ({
        ok: false,
        reason: "already_decided",
        record: makeRecord({ status: "approved", decidedAt: new Date().toISOString() }),
      }),
    });
    const res = await worker.fetch(
      postForm(`/a/${await token()}/decide`, { decision: "denied" }),
      env,
      ctx,
    );
    expect(await res.text()).toContain("Approved");
  });

  it("returns 404 when decide hits a missing approval", async () => {
    const env = makeEnv({ decideApproval: async () => ({ ok: false, reason: "not_found" }) });
    const res = await worker.fetch(
      postForm(`/a/${await token()}/decide`, { decision: "approved" }),
      env,
      ctx,
    );
    expect(res.status).toBe(404);
  });

  it("rejects a decide POST with an invalid token without calling the binding", async () => {
    const decideApproval = vi.fn(
      async (): Promise<DecideResult> => ({ ok: true, record: makeRecord() }),
    );
    const res = await worker.fetch(
      postForm("/a/garbage/decide", { decision: "approved" }),
      makeEnv({ decideApproval }),
      ctx,
    );
    expect(res.status).toBe(404);
    expect(decideApproval).not.toHaveBeenCalled();
  });
});
