# compliance-audit

Run an 8-axis GDPR/AI-Act compliance audit against an `@kajaril/audit-event-mcp` event store.

## When to use

When the user asks to audit, review, or check compliance of an agent's audit log — e.g.:
- "run the compliance audit"
- "check our AI Act compliance"
- "does our event log meet GDPR requirements"

## What you need before running

- Access to the event store: either a local SQLite file, a connection string, or the ability to call `query_events` via MCP
- The client ID whose DO you are auditing

## The 8 axes

Run all 8 axes in sequence. For each, produce `pass | fail | warn` and an evidence snippet (first 3 matching rows, or the count if many).

### Axis 1 — Lawful basis present (GDPR Art. 5–6)
Query: records where `subject_id IS NOT NULL OR event_type = 'human.turn'`.
- **pass**: all such records have `lawful_basis` in `{legitimate_interest, contract, legal_obligation, vital_interest, public_task, consent}`
- **fail**: any such record has `lawful_basis IS NULL`
- **pass**: records with `lawful_basis IS NULL` all have `subject_id IS NULL AND event_type != 'human.turn'`

### Axis 2 — Purpose specificity (GDPR Art. 5(1)(b))
Query: all records.
- **fail**: any `purpose` field is shorter than 10 characters
- **warn**: identical `purpose` value appears in > 20% of total records (boilerplate signal)
- **pass**: otherwise

### Axis 3 — Subject linkage (AI Act Art. 12)
Query: records where `event_type = 'human.turn'`.
- **fail**: any `human.turn` record has `subject_id IS NULL`
- **pass**: all `human.turn` records have non-null `subject_id`

### Axis 4 — Retention bounded (GDPR Art. 5(1)(e))
Query: all records.
- **fail**: any `retention_days > 730` (2 years)
- **pass**: all `retention_days ≤ 730`

### Axis 5 — Chain integrity (tamper-evidence)
Sample: randomly select 10% of records (minimum 10, maximum 200).
For each sampled record, recompute `chain_hash`:
```
input_hash_slot = input_hash ?? input_hash_omitted_reason
chain_hash = SHA-256(id + "|" + event_type + "|" + input_hash_slot + "|" + (prev_hash ?? ""))
```
- **fail**: any recomputed hash does not match stored `chain_hash`
- **pass**: all sampled hashes match

### Axis 6 — Notary coverage (paid tier only)
Query: `SELECT COUNT(*) total, COUNT(merkle_root) notarised FROM audit_events`.
- **skip**: if `total = 0` or if all records have `merkle_root IS NULL` (free tier — skip, do not fail)
- **fail**: `notarised / total < 0.95`
- **warn**: `notarised / total < 0.99`
- **pass**: `notarised / total ≥ 0.95`

### Axis 7 — High-risk event completeness (AI Act Art. 12–13)
Query: sessions that contain at least one `human.turn`.
- **fail**: any such session has zero `tool.call` OR `decision.made` events
- **pass**: every session with `human.turn` also has ≥ 1 `tool.call` or `decision.made`

### Axis 8 — Data minimisation signal (GDPR Art. 5(1)(c))
Query: `SELECT COUNT(*) total, COUNT(payload_ref) with_payload FROM audit_events`.
- **fail**: `with_payload / total > 0.50`
- **warn**: `with_payload / total > 0.20`
- **pass**: `with_payload / total ≤ 0.20`

## Output format

After running all 8 axes, write the result as two blocks:

**Block 1 — JSON** (stdout):
```json
{
  "axes": [
    { "axis": 1, "name": "Lawful basis present", "result": "pass|fail|warn", "evidence": "..." },
    ...
  ],
  "passed": N,
  "failed": N,
  "warned": N,
  "skipped": N,
  "generatedAt": "<ISO-8601 UTC>"
}
```

**Block 2 — Markdown summary** (human-readable, follows the JSON block):
```
## Compliance Audit — <client-id> — <date>

| # | Axis | Result | Evidence |
|---|------|--------|----------|
| 1 | Lawful basis present | ✅ pass | 142 records checked |
...

**Summary**: N passed, N failed, N warned, N skipped
```

## Notes

- Never output `input_hash` values in evidence snippets — hash only, never payload
- Axis 6 skip is not a failure — free tier does not have notary infrastructure
- A single `fail` is sufficient to flag the log as non-compliant for that axis; do not average
- `warn` means the log is technically compliant but has a quality signal worth investigating
