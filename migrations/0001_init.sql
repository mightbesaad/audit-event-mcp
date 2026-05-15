-- Applied by AuditDO on first init via state.storage.sql.exec().
-- Never edit this file after first prod deployment — add 0002_*.sql instead.

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

CREATE INDEX IF NOT EXISTS idx_session   ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS idx_agent     ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_created   ON audit_events(created_at);
