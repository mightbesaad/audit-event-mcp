import { uuidv7 } from "uuidv7";
import {
  type ActionPayload,
  type ApprovalCreateResult,
  type ApprovalRecord,
  type ApprovalStatus,
  type DecideResult,
  defaultTtlSeconds,
  generateApprovalId,
  isValidApprovalIdShape,
  isValidClientIdShape,
  MAX_ACTION_PAYLOAD_CHARS,
  statusOnRead,
} from "@/lib/approval";
import { mintApprovalUrl } from "@/lib/approval-flow";
import {
  buildMerkleProofs,
  canonicalJson,
  computeActionPayloadHash,
  computeChainHash,
  computeInputHash,
  type MerkleProofStep,
} from "@/lib/hash";
import { isM2MScope } from "@/lib/m2m";
import { isValidEmailShape, sendApprovalEmail } from "@/lib/notify";
import {
  ApprovalCreateRequestSchema,
  ApprovalDecideRequestSchema,
  DoRecordRequestSchema,
} from "@/lib/schema";
import type { DossierResult, Env, RecordResult, VerifyResult } from "@/lib/types";

// type alias, not interface — SqlStorage.exec<T> needs the implicit index signature
type ApprovalRow = {
  id: string;
  agent_id: string;
  session_id: string;
  action_summary: string;
  action_payload: string | null;
  action_payload_hash: string | null;
  status: string;
  responder_id: string | null;
  reason: string | null;
  channels: string;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  callback_url: string | null;
};

// Unguessable capability token for the unauthenticated dossier download URL. Uses 256 bits of
// CSPRNG output rather than uuidv7: a dossier link is a bearer capability to a data subject's
// exported records, and uuidv7 is time-ordered (~48 bits are a timestamp, leaking creation time
// and leaving only ~74 random bits) — the wrong primitive for a secret URL.
function dossierToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

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

-- 'timeout' is computed on read and never stored (D3); the CHECK keeps it that way.
-- modifications / policy_ref / escalated_to are reserved for v1.5 verbs (D5) — never repurpose.
-- session_id ties the approval's chain events to the agent's session (D7); action_payload is
-- the canonical-JSON render copy of what was hashed (D6). Both added Day 2, pre-first-deploy.
CREATE TABLE IF NOT EXISTS approvals (
  id                   TEXT PRIMARY KEY,
  agent_id             TEXT NOT NULL,
  session_id           TEXT NOT NULL,
  action_summary       TEXT NOT NULL,
  action_payload       TEXT,
  action_payload_hash  TEXT,
  status               TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','approved','denied')),
  responder_id         TEXT,
  reason               TEXT,
  channels             TEXT NOT NULL DEFAULT '[]',
  created_at           TEXT NOT NULL,
  expires_at           TEXT NOT NULL,
  decided_at           TEXT,
  callback_url         TEXT,
  modifications        TEXT,
  policy_ref           TEXT,
  escalated_to         TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

-- M2M client-credential hashes (decision D2): one row per scope, plaintext never stored.
-- The tenant's own DO is the registry — no cross-tenant credential store to leak or migrate,
-- and rotating one tenant's scope never touches anyone else. Added Day 3, pre-first-deploy.
CREATE TABLE IF NOT EXISTS credentials (
  scope        TEXT PRIMARY KEY CHECK (scope IN ('agent','admin')),
  secret_hash  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  rotated_at   TEXT
);

-- Email-fallback escalations (D4, Day 4, pre-first-deploy): at most one per approval,
-- armed by the worker flow at request time, fired by this DO's alarm. due_at/fired_at are
-- ISO-8601 like every other timestamp here (lexicographic compare works). client_id is
-- redundant with the DO's own name but stored so firing needs no name parsing. Expiry
-- itself stays computed-on-read (D3) — this alarm exists only to SEND, never to decide.
CREATE TABLE IF NOT EXISTS escalations (
  approval_id  TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL,
  email_to     TEXT NOT NULL,
  due_at       TEXT NOT NULL,
  fired_at     TEXT,
  result       TEXT
);
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
    if (request.method === "POST" && url.pathname === "/approval/create")
      return this.handleApprovalCreate(request);
    if (request.method === "POST" && url.pathname === "/approval/get")
      return this.handleApprovalGet(request);
    if (request.method === "POST" && url.pathname === "/approval/decide")
      return this.handleApprovalDecide(request);
    if (request.method === "POST" && url.pathname === "/approval/arm-escalation")
      return this.handleArmEscalation(request);
    if (request.method === "POST" && url.pathname === "/credential/set")
      return this.handleCredentialSet(request);
    if (request.method === "POST" && url.pathname === "/credential/get")
      return this.handleCredentialGet(request);
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

  // Called by CF runtime when the scheduled alarm fires. One alarm serves two jobs
  // (a DO has exactly one): notarization flush and email escalations. Running the notary
  // early because an escalation pulled the alarm forward is harmless — it just signs
  // whatever is pending.
  async alarm(): Promise<void> {
    await this.notarizePending();
    await this.processDueEscalations();
    await this.armNextEscalationAlarm();
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

  // --- approvals (decision D3) ---
  // State machine ported from gvnr lib/approval.ts: pending → approved | denied via /decide;
  // 'timeout' is computed on read the moment expires_at passes — no alarms, nothing stored.
  // Chain events (approval.requested / approval.decided) ride the existing /record path and
  // are emitted by the Worker layer, not here — the chain format stays frozen (D7).

  private approvalRowToRecord(row: ApprovalRow): ApprovalRecord {
    return {
      id: row.id,
      agentId: row.agent_id,
      sessionId: row.session_id,
      actionSummary: row.action_summary,
      actionPayload: row.action_payload ? (JSON.parse(row.action_payload) as ActionPayload) : null,
      actionPayloadHash: row.action_payload_hash,
      status: statusOnRead(row.status as ApprovalStatus, row.expires_at, Date.now()),
      responderId: row.responder_id,
      reason: row.reason,
      channels: JSON.parse(row.channels) as string[],
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      decidedAt: row.decided_at,
      callbackUrl: row.callback_url,
    };
  }

  private readApprovalRow(approvalId: string): ApprovalRow | null {
    if (!isValidApprovalIdShape(approvalId)) return null;
    const rows = this.sql
      .exec<ApprovalRow>(
        `SELECT id, agent_id, session_id, action_summary, action_payload, action_payload_hash,
                status, responder_id, reason, channels, created_at, expires_at, decided_at,
                callback_url
         FROM approvals WHERE id = ?`,
        approvalId,
      )
      .toArray();
    return rows[0] ?? null;
  }

  private async handleApprovalCreate(request: Request): Promise<Response> {
    const raw = await request.json();
    const parsed = ApprovalCreateRequestSchema.safeParse(raw);
    if (!parsed.success) {
      return Response.json(
        { error: "Invalid input", issues: parsed.error.issues },
        { status: 400 },
      );
    }
    const input = parsed.data;

    // Stored and hashed in canonical form (D6): the hash must be re-verifiable from the
    // payload document alone, and what is rendered must be byte-identical to what was hashed.
    let actionPayloadCanonical: string | null = null;
    let actionPayloadHash: string | null = null;
    if (input.actionPayload !== undefined) {
      actionPayloadCanonical = canonicalJson(input.actionPayload);
      if (actionPayloadCanonical.length > MAX_ACTION_PAYLOAD_CHARS) {
        return Response.json(
          {
            error: "Invalid input",
            detail: `actionPayload exceeds ${MAX_ACTION_PAYLOAD_CHARS} chars in canonical JSON — pass a summary-sized payload; large arguments belong behind your own reference`,
          },
          { status: 400 },
        );
      }
      actionPayloadHash = await computeActionPayloadHash(input.actionPayload);
    }

    const id = generateApprovalId();
    const now = Date.now();
    const channels = input.channels ?? [];
    const ttlSeconds = input.ttlSeconds ?? defaultTtlSeconds(channels);
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + ttlSeconds * 1000).toISOString();

    this.sql.exec(
      `INSERT INTO approvals
         (id, agent_id, session_id, action_summary, action_payload, action_payload_hash,
          status, channels, created_at, expires_at, callback_url)
       VALUES (?,?,?,?,?,?,'pending',?,?,?,?)`,
      id,
      input.agentId,
      input.sessionId,
      input.actionSummary,
      actionPayloadCanonical,
      actionPayloadHash,
      JSON.stringify(channels),
      createdAt,
      expiresAt,
      input.callbackUrl ?? null,
    );

    const record: ApprovalRecord = {
      id,
      agentId: input.agentId,
      sessionId: input.sessionId,
      actionSummary: input.actionSummary,
      actionPayload: actionPayloadCanonical
        ? (JSON.parse(actionPayloadCanonical) as ActionPayload)
        : null,
      actionPayloadHash,
      status: "pending",
      responderId: null,
      reason: null,
      channels,
      createdAt,
      expiresAt,
      decidedAt: null,
      callbackUrl: input.callbackUrl ?? null,
    };
    const result: ApprovalCreateResult = { approvalId: id, expiresAt, record };
    return Response.json(result);
  }

  private async handleApprovalGet(request: Request): Promise<Response> {
    const raw = (await request.json()) as { approvalId?: string };
    if (typeof raw.approvalId !== "string") {
      return Response.json({ error: "approvalId required" }, { status: 400 });
    }
    const row = this.readApprovalRow(raw.approvalId);
    if (!row) return Response.json({ error: "approval_not_found" }, { status: 404 });
    return Response.json(this.approvalRowToRecord(row));
  }

  private async handleApprovalDecide(request: Request): Promise<Response> {
    const raw = await request.json();
    const parsed = ApprovalDecideRequestSchema.safeParse(raw);
    if (!parsed.success) {
      return Response.json(
        { error: "Invalid input", issues: parsed.error.issues },
        { status: 400 },
      );
    }
    const input = parsed.data;

    const row = this.readApprovalRow(input.approvalId);
    if (!row) {
      const result: DecideResult = { ok: false, reason: "not_found" };
      return Response.json(result, { status: 404 });
    }
    if (row.status !== "pending") {
      const result: DecideResult = {
        ok: false,
        reason: "already_decided",
        record: this.approvalRowToRecord(row),
      };
      return Response.json(result, { status: 409 });
    }
    if (Date.now() > Date.parse(row.expires_at)) {
      const result: DecideResult = {
        ok: false,
        reason: "expired",
        record: this.approvalRowToRecord(row),
      };
      return Response.json(result, { status: 410 });
    }

    const decidedAt = new Date().toISOString();
    this.sql.exec(
      `UPDATE approvals
       SET status = ?, responder_id = ?, reason = ?, decided_at = ?
       WHERE id = ? AND status = 'pending'`,
      input.decision,
      input.responderId ?? null,
      input.reason ?? null,
      decidedAt,
      input.approvalId,
    );

    const updated = this.readApprovalRow(input.approvalId);
    if (!updated) {
      return Response.json({ ok: false, reason: "not_found" } satisfies DecideResult, {
        status: 404,
      });
    }
    const result: DecideResult = { ok: true, record: this.approvalRowToRecord(updated) };
    return Response.json(result);
  }

  // --- email escalation (decision D4) ---
  // The flow layer arms at request time (it alone knows whether an instant channel
  // delivered); this DO owns WHEN to fire and the still-pending re-check at fire time.
  // Callers are trusted workers — these internal routes are reachable only via the stub.

  private async handleArmEscalation(request: Request): Promise<Response> {
    const raw = (await request.json()) as {
      approvalId?: unknown;
      clientId?: unknown;
      emailTo?: unknown;
      dueAtMs?: unknown;
    };
    if (typeof raw.approvalId !== "string" || !isValidApprovalIdShape(raw.approvalId)) {
      return Response.json({ error: "invalid approvalId" }, { status: 400 });
    }
    if (typeof raw.clientId !== "string" || !isValidClientIdShape(raw.clientId)) {
      return Response.json({ error: "invalid clientId" }, { status: 400 });
    }
    if (typeof raw.emailTo !== "string" || !isValidEmailShape(raw.emailTo)) {
      return Response.json({ error: "invalid emailTo" }, { status: 400 });
    }
    if (typeof raw.dueAtMs !== "number" || !Number.isInteger(raw.dueAtMs) || raw.dueAtMs <= 0) {
      return Response.json({ error: "invalid dueAtMs" }, { status: 400 });
    }

    const row = this.readApprovalRow(raw.approvalId);
    if (!row) return Response.json({ error: "approval_not_found" }, { status: 404 });
    if (statusOnRead(row.status as ApprovalStatus, row.expires_at, Date.now()) !== "pending") {
      return Response.json({ error: "not_pending" }, { status: 409 });
    }

    const dueAt = new Date(raw.dueAtMs).toISOString();
    this.sql.exec(
      `INSERT INTO escalations (approval_id, client_id, email_to, due_at, fired_at, result)
       VALUES (?,?,?,?,NULL,NULL)
       ON CONFLICT(approval_id) DO UPDATE SET email_to = excluded.email_to,
                                              due_at = excluded.due_at`,
      raw.approvalId,
      raw.clientId,
      raw.emailTo,
      dueAt,
    );
    await this.armAlarmAt(raw.dueAtMs);
    return Response.json({ armed: true, dueAt });
  }

  // Single attempt per escalation, mirroring the decision webhook: the row records the
  // outcome and is never retried (outbox is v1.5, DEFERRED.md). 'superseded' means the
  // approval was decided or expired before the email was due — the happy path.
  private async processDueEscalations(): Promise<void> {
    const due = this.sql
      .exec<{ approval_id: string; client_id: string; email_to: string }>(
        "SELECT approval_id, client_id, email_to FROM escalations WHERE fired_at IS NULL AND due_at <= ?",
        new Date().toISOString(),
      )
      .toArray();

    for (const esc of due) {
      let result = "superseded";
      const row = this.readApprovalRow(esc.approval_id);
      if (
        row &&
        statusOnRead(row.status as ApprovalStatus, row.expires_at, Date.now()) === "pending"
      ) {
        const record = this.approvalRowToRecord(row);
        const approvalUrl = await mintApprovalUrl(
          this.env,
          esc.client_id,
          record.id,
          record.expiresAt,
        );
        if (!approvalUrl) {
          // Same fail-closed posture as the unsigned webhook: an approval email whose only
          // job is the decide link is not sent without one.
          result = "skipped_no_link";
        } else {
          result = (
            await sendApprovalEmail(this.env.RESEND_API_KEY, esc.email_to, record, approvalUrl)
          ).status;
        }
      }
      this.sql.exec(
        "UPDATE escalations SET fired_at = ?, result = ? WHERE approval_id = ?",
        new Date().toISOString(),
        result,
        esc.approval_id,
      );
    }
  }

  private async armNextEscalationAlarm(): Promise<void> {
    const next = this.sql
      .exec<{ due_at: string }>(
        "SELECT due_at FROM escalations WHERE fired_at IS NULL ORDER BY due_at ASC LIMIT 1",
      )
      .toArray()[0];
    if (!next) return;
    await this.armAlarmAt(Date.parse(next.due_at));
  }

  // Pull the single alarm earlier when needed; never push it later — the notary's 15-min
  // cadence (scheduleAlarmIfNeeded) keeps its slot when it is already sooner.
  private async armAlarmAt(tMs: number): Promise<void> {
    const existing = await this.state.storage.getAlarm?.();
    if (existing !== null && existing !== undefined && existing <= tMs) return;
    await this.state.storage.setAlarm?.(Math.max(tMs, Date.now()));
  }

  // --- M2M credentials (decision D2) ---
  // The worker generates the secret and hashes it; only the hash ever reaches the DO. The
  // UPSERT keeps created_at from the first issue and stamps rotated_at on every later one,
  // so the row itself documents rotation history's two endpoints.

  private async handleCredentialSet(request: Request): Promise<Response> {
    const raw = (await request.json()) as { scope?: unknown; secretHash?: unknown };
    if (!isM2MScope(raw.scope)) {
      return Response.json({ error: "scope must be 'agent' or 'admin'" }, { status: 400 });
    }
    if (typeof raw.secretHash !== "string" || !/^[0-9a-f]{64}$/.test(raw.secretHash)) {
      return Response.json({ error: "secretHash must be SHA-256 hex" }, { status: 400 });
    }
    const now = new Date().toISOString();
    this.sql.exec(
      `INSERT INTO credentials (scope, secret_hash, created_at, rotated_at)
       VALUES (?,?,?,NULL)
       ON CONFLICT(scope) DO UPDATE SET secret_hash = excluded.secret_hash,
                                        rotated_at = excluded.created_at`,
      raw.scope,
      raw.secretHash,
      now,
    );
    return Response.json({ scope: raw.scope, setAt: now });
  }

  private async handleCredentialGet(request: Request): Promise<Response> {
    const raw = (await request.json()) as { scope?: unknown };
    if (!isM2MScope(raw.scope)) {
      return Response.json({ error: "scope must be 'agent' or 'admin'" }, { status: 400 });
    }
    const rows = this.sql
      .exec<{ secret_hash: string }>(
        "SELECT secret_hash FROM credentials WHERE scope = ?",
        raw.scope,
      )
      .toArray();
    const row = rows[0];
    if (!row) return Response.json({ error: "credential_not_found" }, { status: 404 });
    return Response.json({ secretHash: row.secret_hash });
  }

  // For the notarized rows in a dossier, return row.id → inclusion proof to its merkle_root.
  // Each distinct root is rebuilt from its FULL batch (all events sharing that root in this
  // tenant DO, every subject), so the proof folds to exactly the root the notary signed.
  private async buildDossierProofs(
    rows: Array<{ id: string; merkle_root: string | null }>,
  ): Promise<Map<string, MerkleProofStep[]>> {
    const result = new Map<string, MerkleProofStep[]>();
    const wanted = new Map<string, Set<string>>(); // merkle_root → row ids in this dossier
    for (const row of rows) {
      if (!row.merkle_root) continue;
      const ids = wanted.get(row.merkle_root) ?? new Set<string>();
      ids.add(row.id);
      wanted.set(row.merkle_root, ids);
    }

    for (const [merkleRoot, ids] of wanted) {
      const batch = this.sql
        .exec<{ id: string; chain_hash: string }>(
          "SELECT id, chain_hash FROM audit_events WHERE merkle_root = ? ORDER BY id ASC",
          merkleRoot,
        )
        .toArray();
      if (batch.length === 0) continue;
      const { proofs } = await buildMerkleProofs(
        batch.map((r) => ({ id: r.id, chainHash: r.chain_hash })),
      );
      for (const id of ids) {
        const proof = proofs.get(id);
        if (proof) result.set(id, proof);
      }
    }
    return result;
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

    // payload_ref is intentionally excluded (privacy invariant — locked decision 8).
    // input_hash / input_hash_omitted_reason / prev_hash are included as of Day 5: they are
    // the chain_hash preimage, and without them a dossier cannot be independently
    // re-verified on the public /verify page — they are digests and reasons, never content.
    const rows = this.sql
      .exec<{
        id: string;
        agent_id: string;
        session_id: string;
        event_type: string;
        input_hash: string | null;
        input_hash_omitted_reason: string | null;
        lawful_basis: string | null;
        purpose: string;
        subject_id: string | null;
        retention_days: number;
        prev_hash: string | null;
        chain_hash: string;
        merkle_root: string | null;
        notary_sig: string | null;
        created_at: string;
      }>(
        `SELECT id, agent_id, session_id, event_type, input_hash, input_hash_omitted_reason,
                lawful_basis, purpose, subject_id, retention_days, prev_hash, chain_hash,
                merkle_root, notary_sig, created_at
         FROM audit_events WHERE subject_id = ? ORDER BY created_at ASC`,
        raw.subjectId,
      )
      .toArray();

    // Attach a Merkle inclusion proof to every notarized row (Day-5 security fix). A dossier
    // is a SUBSET of a batch, and all records in a batch carry the same (merkle_root,
    // notary_sig); the proof is what binds THIS record to that signed root, so a verifier
    // cannot be fooled by a borrowed signature stapled onto fabricated records. The proof is
    // built from the full batch (every event sharing the root, across all subjects) — sibling
    // hashes only, never other subjects' ids or content.
    const proofByRowId = await this.buildDossierProofs(rows);
    const enriched = rows.map((row) => {
      const proof = proofByRowId.get(row.id);
      return proof ? { ...row, merkle_proof: proof } : row;
    });

    const ndjson = enriched.map((row) => `${JSON.stringify(row)}\n`).join("");
    const token = dossierToken();
    const key = `dossier/${clientId}/${token}.jsonl`;
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    await this.env.AUDIT_PAYLOADS.put(key, ndjson, {
      httpMetadata: { contentType: "application/x-ndjson" },
      customMetadata: { expiresAt, subjectId: raw.subjectId },
    });

    const result: DossierResult = {
      url: `${baseUrl}/dossier/${clientId}/${token}`,
      expiresAt,
      eventCount: rows.length,
    };
    return Response.json(result);
  }
}
