import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditDO } from "@/do";
import worker from "@/index";
import type { ApprovalCreateResult } from "@/lib/approval";
import type { Env } from "@/lib/types";
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

  beforeEach(() => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
    idFromName = vi.fn((name: string) => name);
    const env = {
      AUDIT_DO: {
        idFromName,
        get: () => ({
          fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
        }),
      } as unknown as Env["AUDIT_DO"],
    } as Env;
    entry = new ApprovalInternal({} as ExecutionContext, env);
  });

  afterEach(() => {
    db.close();
  });

  async function createInDO(): Promise<ApprovalCreateResult> {
    const res = await do_.fetch(
      post("/approval/create", {
        agentId: "agent-test",
        sessionId: "session-test",
        actionSummary: "Test action",
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
});
