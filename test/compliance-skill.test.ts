import type { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import { computeChainHash, computeInputHash } from "../src/lib/hash";

const { DatabaseSync: DBSync } = await import("node:sqlite");

// Minimal schema matching do.ts (without CHECK constraint — not what we're testing here).
const SCHEMA_SQL = `
CREATE TABLE audit_events (
  id                         TEXT PRIMARY KEY,
  agent_id                   TEXT NOT NULL,
  session_id                 TEXT NOT NULL,
  event_type                 TEXT NOT NULL,
  input_hash                 TEXT,
  input_hash_omitted_reason  TEXT,
  payload_ref                TEXT,
  lawful_basis               TEXT,
  purpose                    TEXT NOT NULL,
  subject_id                 TEXT,
  retention_days             INTEGER NOT NULL DEFAULT 365,
  prev_hash                  TEXT,
  chain_hash                 TEXT NOT NULL,
  merkle_root                TEXT,
  notary_sig                 TEXT,
  created_at                 TEXT NOT NULL
);
`;

let idSeq = 0;

function makeDb(): DatabaseSync {
  const db = new DBSync(":memory:");
  db.exec(SCHEMA_SQL);
  return db;
}

type Row = {
  id?: string;
  agentId?: string;
  sessionId?: string;
  eventType?: string;
  inputHash?: string | null;
  inputHashOmittedReason?: string | null;
  payloadRef?: string | null;
  lawfulBasis?: string | null;
  purpose?: string;
  subjectId?: string | null;
  retentionDays?: number;
  prevHash?: string | null;
  chainHash?: string;
  merkleRoot?: string | null;
  createdAt?: string;
};

function insertEvent(db: DatabaseSync, row: Row = {}): void {
  const inputHash = row.inputHash !== undefined ? row.inputHash : null;
  const inputHashOmittedReason =
    row.inputHashOmittedReason !== undefined
      ? row.inputHashOmittedReason
      : inputHash === null
        ? "no_personal_data"
        : null;
  db.prepare(
    `INSERT INTO audit_events
       (id, agent_id, session_id, event_type, input_hash, input_hash_omitted_reason,
        payload_ref, lawful_basis, purpose, subject_id, retention_days, prev_hash,
        chain_hash, merkle_root, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    row.id ?? `id-${String(++idSeq).padStart(4, "0")}`,
    row.agentId ?? "agent-x",
    row.sessionId ?? "session-a",
    row.eventType ?? "tool.call",
    inputHash,
    inputHashOmittedReason,
    row.payloadRef ?? null,
    row.lawfulBasis ?? null,
    row.purpose ?? "Valid purpose description",
    row.subjectId ?? null,
    row.retentionDays ?? 365,
    row.prevHash ?? null,
    row.chainHash ?? "0".repeat(64),
    row.merkleRoot ?? null,
    row.createdAt ?? new Date().toISOString(),
  );
}

// --- Axis implementations mirroring SKILL.md ---

type AxisResult = "pass" | "fail" | "warn" | "skip";

function axis1(db: DatabaseSync): AxisResult {
  const rows = db
    .prepare(
      `SELECT lawful_basis FROM audit_events
       WHERE subject_id IS NOT NULL OR event_type = 'human.turn'`,
    )
    .all() as Array<{ lawful_basis: string | null }>;
  return rows.some((r) => r.lawful_basis === null) ? "fail" : "pass";
}

function axis2(db: DatabaseSync): AxisResult {
  const rows = db.prepare("SELECT purpose FROM audit_events").all() as Array<{
    purpose: string;
  }>;
  if (rows.some((r) => r.purpose.length < 10)) return "fail";
  const total = rows.length;
  if (total === 0) return "pass";
  const counts = new Map<string, number>();
  for (const r of rows) counts.set(r.purpose, (counts.get(r.purpose) ?? 0) + 1);
  const maxCount = Math.max(...counts.values());
  // Only flag boilerplate when the same purpose appears more than once AND in > 20% of records.
  return maxCount > 1 && maxCount / total > 0.2 ? "warn" : "pass";
}

function axis3(db: DatabaseSync): AxisResult {
  const rows = db
    .prepare(`SELECT subject_id FROM audit_events WHERE event_type = 'human.turn'`)
    .all() as Array<{ subject_id: string | null }>;
  return rows.some((r) => r.subject_id === null) ? "fail" : "pass";
}

function axis4(db: DatabaseSync): AxisResult {
  const rows = db.prepare("SELECT id FROM audit_events WHERE retention_days > 730").all() as Array<{
    id: string;
  }>;
  return rows.length > 0 ? "fail" : "pass";
}

async function axis5(db: DatabaseSync): Promise<{ result: AxisResult; broken: string[] }> {
  const rows = db
    .prepare(
      `SELECT id, event_type, input_hash, input_hash_omitted_reason, prev_hash, chain_hash
       FROM audit_events ORDER BY created_at ASC`,
    )
    .all() as Array<{
    id: string;
    event_type: string;
    input_hash: string | null;
    input_hash_omitted_reason: string | null;
    prev_hash: string | null;
    chain_hash: string;
  }>;
  if (rows.length === 0) return { result: "pass", broken: [] };
  const sampleSize = Math.min(Math.max(Math.ceil(rows.length * 0.1), 10), 200);
  const sample = rows.length <= sampleSize ? rows : rows.slice(0, sampleSize);
  const broken: string[] = [];
  for (const row of sample) {
    const inputHashSlot = row.input_hash ?? row.input_hash_omitted_reason ?? "";
    const expected = await computeChainHash({
      id: row.id,
      eventType: row.event_type,
      inputHashSlot,
      prevHash: row.prev_hash,
    });
    if (expected !== row.chain_hash) broken.push(row.id);
  }
  return { result: broken.length > 0 ? "fail" : "pass", broken };
}

function axis6(db: DatabaseSync): AxisResult {
  const row = db
    .prepare(`SELECT COUNT(*) as total, COUNT(merkle_root) as notarised FROM audit_events`)
    .get() as { total: number; notarised: number };
  if (row.total === 0 || row.notarised === 0) return "skip";
  const coverage = row.notarised / row.total;
  if (coverage < 0.95) return "fail";
  if (coverage < 0.99) return "warn";
  return "pass";
}

function axis7(db: DatabaseSync): AxisResult {
  const sessions = db
    .prepare(`SELECT DISTINCT session_id FROM audit_events WHERE event_type = 'human.turn'`)
    .all() as Array<{ session_id: string }>;
  for (const { session_id } of sessions) {
    const row = db
      .prepare(
        `SELECT COUNT(*) as cnt FROM audit_events
         WHERE session_id = ? AND event_type IN ('tool.call', 'decision.made')`,
      )
      .get(session_id) as { cnt: number };
    if (row.cnt === 0) return "fail";
  }
  return "pass";
}

function axis8(db: DatabaseSync): AxisResult {
  const row = db
    .prepare(`SELECT COUNT(*) as total, COUNT(payload_ref) as with_payload FROM audit_events`)
    .get() as { total: number; with_payload: number };
  if (row.total === 0) return "pass";
  const fraction = row.with_payload / row.total;
  if (fraction > 0.5) return "fail";
  if (fraction > 0.2) return "warn";
  return "pass";
}

// --- Tests ---

beforeEach(() => {
  idSeq = 0;
});

describe("Axis 1 — Lawful basis present (GDPR Art. 5–6)", () => {
  it("pass: all personal-data events have lawful_basis", () => {
    const db = makeDb();
    insertEvent(db, {
      subjectId: "user-1",
      lawfulBasis: "contract",
      purpose: "Handle user request for service",
    });
    insertEvent(db, {
      eventType: "human.turn",
      subjectId: "user-1",
      lawfulBasis: "consent",
      purpose: "User message received and logged",
    });
    expect(axis1(db)).toBe("pass");
  });

  it("pass: events without subject_id and not human.turn may have null lawful_basis", () => {
    const db = makeDb();
    insertEvent(db, { eventType: "tool.call", subjectId: null, lawfulBasis: null });
    expect(axis1(db)).toBe("pass");
  });

  it("fail: event with subject_id has null lawful_basis", () => {
    const db = makeDb();
    insertEvent(db, {
      subjectId: "user-1",
      lawfulBasis: null,
      purpose: "Classify lead for routing queue",
    });
    expect(axis1(db)).toBe("fail");
  });

  it("fail: human.turn with null lawful_basis", () => {
    const db = makeDb();
    insertEvent(db, {
      eventType: "human.turn",
      subjectId: "user-1",
      lawfulBasis: null,
      purpose: "User message received and logged",
    });
    expect(axis1(db)).toBe("fail");
  });
});

describe("Axis 2 — Purpose specificity (GDPR Art. 5(1)(b))", () => {
  it("pass: all purposes >= 10 chars and not boilerplate", () => {
    const db = makeDb();
    insertEvent(db, { purpose: "Classify incoming lead for routing" });
    insertEvent(db, { purpose: "Query CRM for account history" });
    insertEvent(db, { purpose: "Route request to billing team" });
    expect(axis2(db)).toBe("pass");
  });

  it("fail: purpose shorter than 10 chars", () => {
    const db = makeDb();
    insertEvent(db, { purpose: "Do thing" }); // 8 chars
    expect(axis2(db)).toBe("fail");
  });

  it("warn: same purpose on > 20% of records (boilerplate signal)", () => {
    const db = makeDb();
    const boilerplate = "Process input";
    // 2/4 = 50% share the same purpose
    insertEvent(db, { purpose: boilerplate });
    insertEvent(db, { purpose: boilerplate });
    insertEvent(db, { purpose: "Query CRM for account history" });
    insertEvent(db, { purpose: "Route request to billing team" });
    expect(axis2(db)).toBe("warn");
  });
});

describe("Axis 3 — Subject linkage on human.turn (AI Act Art. 12)", () => {
  it("pass: all human.turn events have subject_id", () => {
    const db = makeDb();
    insertEvent(db, {
      eventType: "human.turn",
      subjectId: "user-1",
      lawfulBasis: "consent",
      purpose: "User message received and logged",
    });
    insertEvent(db, { eventType: "tool.call", subjectId: null, purpose: "Search knowledge base" });
    expect(axis3(db)).toBe("pass");
  });

  it("pass: no human.turn events (nothing to check)", () => {
    const db = makeDb();
    insertEvent(db, { eventType: "tool.call", purpose: "Internal system call" });
    expect(axis3(db)).toBe("pass");
  });

  it("fail: human.turn event missing subject_id", () => {
    const db = makeDb();
    insertEvent(db, {
      eventType: "human.turn",
      subjectId: null,
      purpose: "User message received and logged",
    });
    expect(axis3(db)).toBe("fail");
  });
});

describe("Axis 4 — Retention bounded (GDPR Art. 5(1)(e))", () => {
  it("pass: all retention_days <= 730", () => {
    const db = makeDb();
    insertEvent(db, { retentionDays: 365 });
    insertEvent(db, { retentionDays: 730 });
    expect(axis4(db)).toBe("pass");
  });

  it("fail: one record has retention_days = 731", () => {
    const db = makeDb();
    insertEvent(db, { retentionDays: 365 });
    insertEvent(db, { retentionDays: 731 });
    expect(axis4(db)).toBe("fail");
  });
});

describe("Axis 5 — Chain integrity (tamper-evidence)", () => {
  it("pass: empty store", async () => {
    expect((await axis5(makeDb())).result).toBe("pass");
  });

  it("pass: 3-event chain with correct hashes", async () => {
    const db = makeDb();

    const slot0 = await computeInputHash({ step: 0 });
    const h0 = await computeChainHash({
      id: "e0",
      eventType: "tool.call",
      inputHashSlot: slot0,
      prevHash: null,
    });
    insertEvent(db, {
      id: "e0",
      eventType: "tool.call",
      inputHash: slot0,
      inputHashOmittedReason: null,
      chainHash: h0,
      prevHash: null,
      createdAt: "2026-01-01T00:00:00.000Z",
    });

    const slot1 = await computeInputHash({ step: 1 });
    const h1 = await computeChainHash({
      id: "e1",
      eventType: "tool.result",
      inputHashSlot: slot1,
      prevHash: h0,
    });
    insertEvent(db, {
      id: "e1",
      eventType: "tool.result",
      inputHash: slot1,
      inputHashOmittedReason: null,
      chainHash: h1,
      prevHash: h0,
      createdAt: "2026-01-01T00:00:01.000Z",
    });

    // Third event uses omitted-reason (no_personal_data is the default)
    const h2 = await computeChainHash({
      id: "e2",
      eventType: "decision.made",
      inputHashSlot: "no_personal_data",
      prevHash: h1,
    });
    insertEvent(db, {
      id: "e2",
      eventType: "decision.made",
      chainHash: h2,
      prevHash: h1,
      createdAt: "2026-01-01T00:00:02.000Z",
    });

    const result = await axis5(db);
    expect(result.result).toBe("pass");
    expect(result.broken).toHaveLength(0);
  });

  it("fail: tampered chain_hash is detected", async () => {
    const db = makeDb();
    const slot0 = await computeInputHash({ step: 0 });
    const h0 = await computeChainHash({
      id: "e0",
      eventType: "tool.call",
      inputHashSlot: slot0,
      prevHash: null,
    });
    insertEvent(db, {
      id: "e0",
      eventType: "tool.call",
      inputHash: slot0,
      inputHashOmittedReason: null,
      chainHash: h0,
      prevHash: null,
    });
    db.prepare(
      "UPDATE audit_events SET chain_hash = 'deadbeef' || substr(chain_hash, 9) WHERE id = 'e0'",
    ).run();
    const result = await axis5(db);
    expect(result.result).toBe("fail");
    expect(result.broken).toContain("e0");
  });
});

describe("Axis 6 — Notary coverage (paid tier)", () => {
  it("skip: empty store", () => {
    expect(axis6(makeDb())).toBe("skip");
  });

  it("skip: all merkle_root null (free tier)", () => {
    const db = makeDb();
    insertEvent(db, { merkleRoot: null });
    insertEvent(db, { merkleRoot: null });
    expect(axis6(db)).toBe("skip");
  });

  it("pass: 100% notarised", () => {
    const db = makeDb();
    const root = "a".repeat(64);
    insertEvent(db, { merkleRoot: root });
    insertEvent(db, { merkleRoot: root });
    expect(axis6(db)).toBe("pass");
  });

  it("warn: 95% notarised (>= 95% but < 99%)", () => {
    const db = makeDb();
    const root = "a".repeat(64);
    for (let i = 0; i < 95; i++) insertEvent(db, { merkleRoot: root });
    for (let i = 0; i < 5; i++) insertEvent(db, { merkleRoot: null });
    expect(axis6(db)).toBe("warn");
  });

  it("fail: 5% notarised (< 95%)", () => {
    const db = makeDb();
    const root = "a".repeat(64);
    insertEvent(db, { merkleRoot: root });
    for (let i = 0; i < 19; i++) insertEvent(db, { merkleRoot: null });
    expect(axis6(db)).toBe("fail");
  });
});

describe("Axis 7 — High-risk event completeness (AI Act Art. 12–13)", () => {
  it("pass: session with human.turn also has tool.call", () => {
    const db = makeDb();
    insertEvent(db, {
      sessionId: "s1",
      eventType: "human.turn",
      subjectId: "user-1",
      purpose: "User message received and logged",
    });
    insertEvent(db, {
      sessionId: "s1",
      eventType: "tool.call",
      purpose: "Call external search API",
    });
    expect(axis7(db)).toBe("pass");
  });

  it("pass: session with human.turn also has decision.made", () => {
    const db = makeDb();
    insertEvent(db, {
      sessionId: "s1",
      eventType: "human.turn",
      subjectId: "user-1",
      purpose: "User message received and logged",
    });
    insertEvent(db, {
      sessionId: "s1",
      eventType: "decision.made",
      purpose: "Route lead to enterprise queue",
    });
    expect(axis7(db)).toBe("pass");
  });

  it("pass: sessions without human.turn are not checked", () => {
    const db = makeDb();
    insertEvent(db, { sessionId: "s1", eventType: "tool.call", purpose: "Background system job" });
    expect(axis7(db)).toBe("pass");
  });

  it("fail: session has human.turn but no tool.call or decision.made", () => {
    const db = makeDb();
    insertEvent(db, {
      sessionId: "s1",
      eventType: "human.turn",
      subjectId: "user-1",
      purpose: "User message received and logged",
    });
    insertEvent(db, {
      sessionId: "s1",
      eventType: "tool.result",
      purpose: "External API response",
    });
    expect(axis7(db)).toBe("fail");
  });
});

describe("Axis 8 — Data minimisation signal (GDPR Art. 5(1)(c))", () => {
  it("pass: empty store", () => {
    expect(axis8(makeDb())).toBe("pass");
  });

  it("pass: no payload_refs", () => {
    const db = makeDb();
    insertEvent(db, { payloadRef: null });
    insertEvent(db, { payloadRef: null });
    expect(axis8(db)).toBe("pass");
  });

  it("warn: > 20% have payload_ref", () => {
    const db = makeDb();
    // 2/7 ≈ 28.6% > 20%
    insertEvent(db, { payloadRef: "r2://bucket/key-1" });
    insertEvent(db, { payloadRef: "r2://bucket/key-2" });
    for (let i = 0; i < 5; i++) insertEvent(db, { payloadRef: null });
    expect(axis8(db)).toBe("warn");
  });

  it("fail: > 50% have payload_ref", () => {
    const db = makeDb();
    // 3/5 = 60% > 50%
    insertEvent(db, { payloadRef: "r2://bucket/key-1" });
    insertEvent(db, { payloadRef: "r2://bucket/key-2" });
    insertEvent(db, { payloadRef: "r2://bucket/key-3" });
    insertEvent(db, { payloadRef: null });
    insertEvent(db, { payloadRef: null });
    expect(axis8(db)).toBe("fail");
  });
});
