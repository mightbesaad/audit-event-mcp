import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DatabaseSync } from "node:sqlite";
import { AuditDO } from "@/do";
import type { DossierResult, RecordResult, VerifyResult } from "@/lib/types";
import { fakeEnv, makeMockNotary, makeMockR2, makeState, post } from "./harness";

// node:sqlite is a stable built-in since Node 22.5.
// It's dynamically required here to avoid import errors on older Node.
const { DatabaseSync: DBSync } = await import("node:sqlite");

const DOSSIER_HEADERS = { "X-Client-Id": "client-test", "X-Base-Url": "https://audit.example.com" };

const BASE_EVENT = {
  eventType: "tool.call" as const,
  purpose: "unit test",
  sessionId: "s-test",
  agentId: "agent-test",
};

describe("AuditDO", () => {
  let db: DatabaseSync;
  let do_: AuditDO;

  beforeEach(() => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
  });

  afterEach(() => {
    db.close();
  });

  // --- handleRecord ---

  it("record with input returns id and chainHash", async () => {
    const res = await do_.fetch(post("/record", { ...BASE_EVENT, input: { x: 1 } }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as RecordResult;
    expect(body.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    expect(body.chainHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("record with inputHashOmittedReason returns id and chainHash", async () => {
    const res = await do_.fetch(
      post("/record", { ...BASE_EVENT, inputHashOmittedReason: "no_personal_data" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as RecordResult;
    expect(body.chainHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("record without agentId returns 400", async () => {
    const { agentId: _, ...noAgent } = BASE_EVENT;
    const res = await do_.fetch(post("/record", { ...noAgent, input: {} }));
    expect(res.status).toBe(400);
  });

  it("record with both input and omittedReason returns 400 (XOR violation)", async () => {
    const res = await do_.fetch(
      post("/record", {
        ...BASE_EVENT,
        input: { x: 1 },
        inputHashOmittedReason: "no_personal_data",
      }),
    );
    expect(res.status).toBe(400);
  });

  it("record with neither input nor omittedReason returns 400 (XOR violation)", async () => {
    const res = await do_.fetch(post("/record", BASE_EVENT));
    expect(res.status).toBe(400);
  });

  // --- chain wiring ---

  it("second record's prev_hash equals first record's chainHash", async () => {
    const r1 = (await (
      await do_.fetch(post("/record", { ...BASE_EVENT, input: { step: 1 } }))
    ).json()) as RecordResult;

    const r2 = (await (
      await do_.fetch(post("/record", { ...BASE_EVENT, input: { step: 2 } }))
    ).json()) as RecordResult;

    // Confirm chain wiring by inspecting stored prev_hash directly via node:sqlite
    const row = db
      .prepare("SELECT prev_hash FROM audit_events WHERE id = ?")
      .get(r2.id) as { prev_hash: string } | undefined;

    expect(row?.prev_hash).toBe(r1.chainHash);
  });

  it("first record has null prev_hash", async () => {
    const r1 = (await (
      await do_.fetch(post("/record", { ...BASE_EVENT, input: { step: 1 } }))
    ).json()) as RecordResult;

    const row = db
      .prepare("SELECT prev_hash FROM audit_events WHERE id = ?")
      .get(r1.id) as { prev_hash: string | null } | undefined;

    expect(row?.prev_hash).toBeNull();
  });

  // --- handleVerify ---

  it("verify on clean 3-event log returns verified=3 broken=[]", async () => {
    for (let i = 0; i < 3; i++) {
      await do_.fetch(post("/record", { ...BASE_EVENT, input: { i } }));
    }
    const res = await do_.fetch(post("/verify", {}));
    const body = (await res.json()) as VerifyResult;
    expect(body.verified).toBe(3);
    expect(body.broken).toHaveLength(0);
  });

  it("verify detects a tampered chain_hash", async () => {
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { x: 1 } }));
    // Tamper with the stored chain_hash directly via node:sqlite
    db.prepare(
      "UPDATE audit_events SET chain_hash = 'deadbeef' || substr(chain_hash, 9)",
    ).run();

    const res = await do_.fetch(post("/verify", {}));
    const body = (await res.json()) as VerifyResult;
    expect(body.broken).toHaveLength(1);
    expect(body.broken[0]?.actual).toMatch(/^deadbeef/);
    expect(body.broken[0]?.expected).not.toMatch(/^deadbeef/);
  });

  it("verify with fromId only checks events from that id onwards", async () => {
    // Insert r1 then backdate it so r2/r3 have a strictly later created_at.
    // Required because all inserts in a single test tick land in the same millisecond
    // and the verify query uses `created_at >= r2.created_at`.
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { i: 0 } }));
    db.prepare("UPDATE audit_events SET created_at = '2000-01-01T00:00:00.000Z'").run();

    const r2 = (await (
      await do_.fetch(post("/record", { ...BASE_EVENT, input: { i: 1 } }))
    ).json()) as RecordResult;
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { i: 2 } }));

    const res = await do_.fetch(post("/verify", { fromId: r2.id }));
    const body = (await res.json()) as VerifyResult;
    expect(body.verified).toBe(2);
    expect(body.broken).toHaveLength(0);
  });

  // --- handleQuery ---

  it("query without filters returns all events", async () => {
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { i: 0 } }));
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { i: 1 } }));
    const res = await do_.fetch(post("/query", {}));
    const body = (await res.json()) as { events: unknown[]; count: number };
    expect(body.count).toBe(2);
    expect(body.events).toHaveLength(2);
  });

  it("query filters by sessionId", async () => {
    await do_.fetch(post("/record", { ...BASE_EVENT, sessionId: "session-A", input: { i: 0 } }));
    await do_.fetch(post("/record", { ...BASE_EVENT, sessionId: "session-B", input: { i: 1 } }));
    const res = await do_.fetch(post("/query", { sessionId: "session-A" }));
    const body = (await res.json()) as { events: unknown[]; count: number };
    expect(body.count).toBe(1);
  });

  it("query never returns input_hash field", async () => {
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { sensitive: "data" } }));
    const res = await do_.fetch(post("/query", {}));
    const body = (await res.json()) as { events: Record<string, unknown>[] };
    for (const event of body.events) {
      expect(event).not.toHaveProperty("input_hash");
    }
  });

  // --- handleDossier ---

  it("dossier without subjectId returns 400", async () => {
    const res = await do_.fetch(post("/dossier", {}));
    expect(res.status).toBe(400);
  });

  it("dossier without R2 returns 503", async () => {
    const res = await do_.fetch(post("/dossier", { subjectId: "user-1" }, DOSSIER_HEADERS));
    expect(res.status).toBe(503);
  });

  it("dossier with matching events returns 200 with correct eventCount and url", async () => {
    const r2 = makeMockR2();
    const doR2 = new AuditDO(makeState(db), { ...fakeEnv, AUDIT_PAYLOADS: r2 });
    await doR2.fetch(post("/record", { ...BASE_EVENT, subjectId: "user-1", input: { x: 1 } }));
    await doR2.fetch(post("/record", { ...BASE_EVENT, subjectId: "user-1", input: { x: 2 } }));
    await doR2.fetch(post("/record", { ...BASE_EVENT, subjectId: "user-2", input: { x: 3 } }));

    const res = await doR2.fetch(post("/dossier", { subjectId: "user-1" }, DOSSIER_HEADERS));
    expect(res.status).toBe(200);
    const body = (await res.json()) as DossierResult;
    expect(body.eventCount).toBe(2);
    expect(body.url).toContain("client-test");
    expect(body.url).toContain("https://audit.example.com/dossier/");
    expect(body.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("dossier with no matching events returns 200 with eventCount 0", async () => {
    const r2 = makeMockR2();
    const doR2 = new AuditDO(makeState(db), { ...fakeEnv, AUDIT_PAYLOADS: r2 });
    const res = await doR2.fetch(post("/dossier", { subjectId: "nobody" }, DOSSIER_HEADERS));
    expect(res.status).toBe(200);
    const body = (await res.json()) as DossierResult;
    expect(body.eventCount).toBe(0);
    expect(body.url).toContain("https://audit.example.com/dossier/");
  });

  it("dossier does not return input_hash in exported events", async () => {
    const r2 = makeMockR2();
    let capturedBody = "";
    const origPut = (r2 as unknown as Record<string, unknown>).put as (
      k: string,
      v: unknown,
      o?: unknown,
    ) => unknown;
    (r2 as unknown as Record<string, unknown>).put = async (
      k: string,
      v: unknown,
      o?: unknown,
    ) => {
      capturedBody = String(v);
      return origPut(k, v, o);
    };

    const doR2 = new AuditDO(makeState(db), { ...fakeEnv, AUDIT_PAYLOADS: r2 });
    await doR2.fetch(post("/record", { ...BASE_EVENT, subjectId: "user-1", input: { secret: "x" } }));
    await doR2.fetch(post("/dossier", { subjectId: "user-1" }, DOSSIER_HEADERS));

    expect(capturedBody).not.toContain("input_hash");
  });

  // --- alarm / notarization ---

  it("alarm is no-op when NOTARY not bound", async () => {
    await do_.fetch(post("/record", { ...BASE_EVENT, input: { x: 1 } }));
    await do_.alarm();
    const row = db
      .prepare("SELECT merkle_root FROM audit_events LIMIT 1")
      .get() as { merkle_root: string | null } | undefined;
    expect(row?.merkle_root).toBeNull();
  });

  it("alarm stamps merkle_root and notary_sig on all pending events", async () => {
    const notary = makeMockNotary();
    const doN = new AuditDO(makeState(db), { ...fakeEnv, NOTARY: notary });
    await doN.fetch(post("/record", { ...BASE_EVENT, input: { x: 1 } }));
    await doN.fetch(post("/record", { ...BASE_EVENT, input: { x: 2 } }));
    await doN.alarm();
    const rows = db
      .prepare("SELECT merkle_root, notary_sig FROM audit_events")
      .all() as Array<{ merkle_root: string | null; notary_sig: string | null }>;
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.merkle_root).not.toBeNull();
      expect(row.notary_sig).not.toBeNull();
    }
  });

  it("all events in a batch share the same merkle_root", async () => {
    const notary = makeMockNotary();
    const doN = new AuditDO(makeState(db), { ...fakeEnv, NOTARY: notary });
    await doN.fetch(post("/record", { ...BASE_EVENT, input: { x: 1 } }));
    await doN.fetch(post("/record", { ...BASE_EVENT, input: { x: 2 } }));
    await doN.alarm();
    const roots = db
      .prepare("SELECT DISTINCT merkle_root FROM audit_events")
      .all() as Array<{ merkle_root: string }>;
    expect(roots).toHaveLength(1);
  });

  it("second alarm after all events notarized is a no-op", async () => {
    const notary = makeMockNotary();
    let callCount = 0;
    const countingNotary: Fetcher = {
      async fetch(_req: RequestInfo, _init?: RequestInit) {
        callCount++;
        return Response.json({ merkleRoot: "a".repeat(64), notarySig: "b".repeat(128) });
      },
    } as unknown as Fetcher;
    const doN = new AuditDO(makeState(db), { ...fakeEnv, NOTARY: countingNotary });
    await doN.fetch(post("/record", { ...BASE_EVENT, input: { x: 1 } }));
    await doN.alarm();
    expect(callCount).toBe(1);
    await doN.alarm(); // all events already notarized — should not call notary
    expect(callCount).toBe(1);

    void notary; // suppress unused variable warning
  });

  // --- routing ---

  it("unknown path returns 404", async () => {
    const res = await do_.fetch(
      new Request("https://do-internal/unknown", { method: "POST", body: "{}" }),
    );
    expect(res.status).toBe(404);
  });
});
