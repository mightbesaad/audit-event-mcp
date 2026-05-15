import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DatabaseSync, SqliteValue } from "node:sqlite";
import { AuditDO } from "@/do";
import type { Env, RecordResult, VerifyResult } from "@/lib/types";

// node:sqlite is a stable built-in since Node 22.5.
// It's dynamically required here to avoid import errors on older Node.
const { DatabaseSync: DBSync } = await import("node:sqlite");

// --- SqlStorage adapter ---
// Wraps node:sqlite DatabaseSync to satisfy the SqlStorage interface used by AuditDO.
// Routing: multi-statement DDL → exec(); SELECT → prepare().all(); everything else → prepare().run().
function makeSqlStorage(db: DatabaseSync) {
  return {
    exec<T>(sql: string, ...params: unknown[]) {
      const trimmed = sql.trimStart().toUpperCase();

      // Multi-statement SQL (e.g., SCHEMA_SQL with CREATE TABLE + CREATE INDEX × 3)
      if (trimmed.split(";").filter((s) => s.trim()).length > 1) {
        db.exec(sql);
        return { toArray: (): T[] => [] };
      }

      const stmt = db.prepare(sql);

      if (trimmed.startsWith("SELECT")) {
        const rows =
          params.length > 0
            ? stmt.all(...(params as SqliteValue[]))
            : stmt.all();
        return { toArray: (): T[] => rows as unknown as T[] };
      }

      // INSERT / UPDATE / DELETE — run(), no rows returned
      if (params.length > 0) {
        stmt.run(...(params as SqliteValue[]));
      } else {
        stmt.run();
      }
      return { toArray: (): T[] => [] };
    },
  };
}

function makeState(db: DatabaseSync): DurableObjectState {
  return {
    storage: { sql: makeSqlStorage(db) },
  } as unknown as DurableObjectState;
}

const fakeEnv = {} as unknown as Env;

function post(path: string, body: unknown): Request {
  return new Request(`https://do-internal${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

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

  it("dossier with subjectId returns 501 (not yet implemented)", async () => {
    const res = await do_.fetch(post("/dossier", { subjectId: "user-1" }));
    expect(res.status).toBe(501);
  });

  // --- routing ---

  it("unknown path returns 404", async () => {
    const res = await do_.fetch(
      new Request("https://do-internal/unknown", { method: "POST", body: "{}" }),
    );
    expect(res.status).toBe(404);
  });
});
