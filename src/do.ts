import { uuidv7 } from "uuidv7";
import { computeChainHash, computeInputHash } from "@/lib/hash";
import { DoRecordRequestSchema } from "@/lib/schema";
import type { DossierResult, Env, RecordResult, VerifyResult } from "@/lib/types";

// Schema is applied on first DO init. migrations/0001_init.sql is the canonical doc copy.
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS audit_events (
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
  stripe_card_id             TEXT,
  stripe_authorization_id    TEXT,
  created_at                 TEXT NOT NULL,
  CHECK (input_hash IS NOT NULL OR input_hash_omitted_reason IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_session ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS idx_agent   ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_created ON audit_events(created_at);
`;

export class AuditDO implements DurableObject {
  private readonly sql: SqlStorage;
  private readonly env: Env;
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState, env: Env) {
    this.sql = state.storage.sql;
    this.env = env;
    this.state = state;
    this.sql.exec(SCHEMA_SQL);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/record") return this.handleRecord(request);
    if (request.method === "POST" && url.pathname === "/verify") return this.handleVerify(request);
    if (request.method === "POST" && url.pathname === "/query") return this.handleQuery(request);
    if (request.method === "POST" && url.pathname === "/dossier")
      return this.handleDossier(request);
    return Response.json({ error: "Not Found" }, { status: 404 });
  }

  private async handleRecord(request: Request): Promise<Response> {
    const raw = await request.json();
    const parsed = DoRecordRequestSchema.safeParse(raw);
    if (!parsed.success) {
      return Response.json(
        { error: "Invalid input", issues: parsed.error.issues },
        { status: 400 },
      );
    }

    const input = parsed.data;

    const lastRows = this.sql
      .exec<{ chain_hash: string }>(
        "SELECT chain_hash FROM audit_events ORDER BY created_at DESC LIMIT 1",
      )
      .toArray();
    const prevHash = lastRows[0]?.chain_hash ?? null;

    let inputHash: string | null = null;
    let inputHashOmittedReason: string | null = null;

    if (input.input !== undefined) {
      inputHash = await computeInputHash(input.input);
    } else {
      inputHashOmittedReason = input.inputHashOmittedReason ?? null;
    }

    // inputHashSlot: never empty string — distinctness of omission reason is intentional
    const inputHashSlot = inputHash ?? inputHashOmittedReason ?? "";
    const id = uuidv7();
    const chainHash = await computeChainHash({
      id,
      eventType: input.eventType,
      inputHashSlot,
      prevHash,
    });
    const createdAt = new Date().toISOString();

    this.sql.exec(
      `INSERT INTO audit_events
         (id, agent_id, session_id, event_type, input_hash, input_hash_omitted_reason,
          lawful_basis, purpose, subject_id, retention_days,
          prev_hash, chain_hash, created_at,
          stripe_card_id, stripe_authorization_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      id,
      input.agentId,
      input.sessionId,
      input.eventType,
      inputHash,
      inputHashOmittedReason,
      input.lawfulBasis ?? null,
      input.purpose,
      input.subjectId ?? null,
      input.retentionDays ?? 365,
      prevHash,
      chainHash,
      createdAt,
      input.stripeCardId ?? null,
      input.stripeAuthorizationId ?? null,
    );

    await this.scheduleAlarmIfNeeded();

    const result: RecordResult = { id, chainHash };
    return Response.json(result);
  }

  private async handleVerify(request: Request): Promise<Response> {
    const raw = (await request.json()) as { fromId?: string; limit?: number };
    const limit = Math.min(raw.limit ?? 100, 1000);

    const rows = raw.fromId
      ? this.sql
          .exec<{
            id: string;
            event_type: string;
            input_hash: string | null;
            input_hash_omitted_reason: string | null;
            prev_hash: string | null;
            chain_hash: string;
          }>(
            `SELECT id, event_type, input_hash, input_hash_omitted_reason, prev_hash, chain_hash
             FROM audit_events
             WHERE created_at >= (SELECT created_at FROM audit_events WHERE id = ?)
             ORDER BY created_at ASC LIMIT ?`,
            raw.fromId,
            limit,
          )
          .toArray()
      : this.sql
          .exec<{
            id: string;
            event_type: string;
            input_hash: string | null;
            input_hash_omitted_reason: string | null;
            prev_hash: string | null;
            chain_hash: string;
          }>(
            `SELECT id, event_type, input_hash, input_hash_omitted_reason, prev_hash, chain_hash
             FROM audit_events ORDER BY created_at ASC LIMIT ?`,
            limit,
          )
          .toArray();

    const broken: VerifyResult["broken"] = [];
    for (const row of rows) {
      const inputHashSlot = row.input_hash ?? row.input_hash_omitted_reason ?? "";
      const expected = await computeChainHash({
        id: row.id,
        eventType: row.event_type,
        inputHashSlot,
        prevHash: row.prev_hash,
      });
      if (expected !== row.chain_hash) {
        broken.push({ id: row.id, expected, actual: row.chain_hash });
      }
    }

    const result: VerifyResult = { verified: rows.length, broken };
    return Response.json(result);
  }

  private async handleQuery(request: Request): Promise<Response> {
    const raw = (await request.json()) as {
      sessionId?: string;
      eventType?: string;
      agentId?: string;
      fromDate?: string;
      toDate?: string;
      limit?: number;
    };
    const limit = Math.min(raw.limit ?? 50, 500);

    const conditions: string[] = [];
    const bindings: unknown[] = [];

    if (raw.sessionId) {
      conditions.push("session_id = ?");
      bindings.push(raw.sessionId);
    }
    if (raw.eventType) {
      conditions.push("event_type = ?");
      bindings.push(raw.eventType);
    }
    if (raw.agentId) {
      conditions.push("agent_id = ?");
      bindings.push(raw.agentId);
    }
    if (raw.fromDate) {
      conditions.push("created_at >= ?");
      bindings.push(raw.fromDate);
    }
    if (raw.toDate) {
      conditions.push("created_at <= ?");
      bindings.push(raw.toDate);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    bindings.push(limit);

    // input_hash is intentionally excluded from query results
    const rows = this.sql
      .exec<{
        id: string;
        agent_id: string;
        session_id: string;
        event_type: string;
        lawful_basis: string | null;
        purpose: string;
        subject_id: string | null;
        retention_days: number;
        prev_hash: string | null;
        chain_hash: string;
        merkle_root: string | null;
        created_at: string;
      }>(
        `SELECT id, agent_id, session_id, event_type, lawful_basis, purpose,
                subject_id, retention_days, prev_hash, chain_hash, merkle_root, created_at
         FROM audit_events ${where} ORDER BY created_at DESC LIMIT ?`,
        ...bindings,
      )
      .toArray();

    return Response.json({ events: rows, count: rows.length });
  }

  // Called by CF runtime when the scheduled alarm fires — flushes all pending events.
  async alarm(): Promise<void> {
    await this.notarizePending();
  }

  private async scheduleAlarmIfNeeded(): Promise<void> {
    const existing = await this.state.storage.getAlarm?.();
    if (existing !== null && existing !== undefined) return;
    await this.state.storage.setAlarm?.(Date.now() + 15 * 60 * 1000);
  }

  private async notarizePending(): Promise<void> {
    if (!this.env.NOTARY) return;
    const pending = this.sql
      .exec<{ id: string; chain_hash: string }>(
        "SELECT id, chain_hash FROM audit_events WHERE merkle_root IS NULL ORDER BY id ASC LIMIT 1000",
      )
      .toArray();
    if (pending.length === 0) return;
    const events = pending.map((r) => ({ id: r.id, chainHash: r.chain_hash }));
    try {
      const res = await this.env.NOTARY.fetch("https://notary-internal/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events }),
      });
      if (!res.ok) return;
      const { merkleRoot, notarySig } = (await res.json()) as {
        merkleRoot: string;
        notarySig: string;
      };
      for (const { id } of pending) {
        this.sql.exec(
          "UPDATE audit_events SET merkle_root = ?, notary_sig = ? WHERE id = ?",
          merkleRoot,
          notarySig,
          id,
        );
      }
    } catch {
      // Notary unavailable — events remain pending for next alarm cycle
    }
  }

  private async handleDossier(request: Request): Promise<Response> {
    const raw = (await request.json()) as { subjectId?: string };
    if (!raw.subjectId) {
      return Response.json({ error: "subjectId required" }, { status: 400 });
    }
    if (!this.env.AUDIT_PAYLOADS) {
      return Response.json({ error: "R2 not configured" }, { status: 503 });
    }

    const clientId = request.headers.get("X-Client-Id") ?? "unknown";
    const baseUrl = request.headers.get("X-Base-Url") ?? "";

    // input_hash and payload_ref are intentionally excluded
    const rows = this.sql
      .exec<{
        id: string;
        agent_id: string;
        session_id: string;
        event_type: string;
        lawful_basis: string | null;
        purpose: string;
        subject_id: string | null;
        retention_days: number;
        chain_hash: string;
        merkle_root: string | null;
        notary_sig: string | null;
        created_at: string;
      }>(
        `SELECT id, agent_id, session_id, event_type, lawful_basis, purpose,
                subject_id, retention_days, chain_hash, merkle_root, notary_sig, created_at
         FROM audit_events WHERE subject_id = ? ORDER BY created_at ASC`,
        raw.subjectId,
      )
      .toArray();

    const ndjson = rows.map((row) => `${JSON.stringify(row)}\n`).join("");
    const uuid = uuidv7();
    const key = `dossier/${clientId}/${uuid}.jsonl`;
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    await this.env.AUDIT_PAYLOADS.put(key, ndjson, {
      httpMetadata: { contentType: "application/x-ndjson" },
      customMetadata: { expiresAt, subjectId: raw.subjectId },
    });

    const result: DossierResult = {
      url: `${baseUrl}/dossier/${clientId}/${uuid}`,
      expiresAt,
      eventCount: rows.length,
    };
    return Response.json(result);
  }
}
