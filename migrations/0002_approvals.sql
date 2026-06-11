-- Applied by AuditDO on init via state.storage.sql.exec() — CREATE TABLE IF NOT EXISTS is
-- idempotent, so existing tenant DOs pick this up on their next request with no migration step.
-- Doc copy only; the canonical SQL lives in SCHEMA_SQL in src/do.ts.

-- 'timeout' is computed on read and never stored (decision D3); the CHECK keeps it that way.
-- modifications / policy_ref / escalated_to are reserved for v1.5 verbs (decision D5) —
-- never repurpose them.

CREATE TABLE IF NOT EXISTS approvals (
  id                   TEXT PRIMARY KEY,
  agent_id             TEXT NOT NULL,
  action_summary       TEXT NOT NULL,
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
