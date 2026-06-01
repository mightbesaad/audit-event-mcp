# @kajaril/audit-event-mcp

Agent steward infrastructure — hash-chained audit log with Merkle notarisation and a GDPR/AI-Act compliance skill.

[![CI](https://github.com/mightbesaad/audit-event-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/mightbesaad/audit-event-mcp/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@kajaril/audit-event-mcp)](https://www.npmjs.com/package/@kajaril/audit-event-mcp)
[![npm downloads](https://img.shields.io/npm/dw/@kajaril/audit-event-mcp)](https://www.npmjs.com/package/@kajaril/audit-event-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Smithery](https://smithery.ai/badge/@kajaril/audit-event)](https://smithery.ai/server/@kajaril/audit-event)

---

## What it does

- Records agent events (tool calls, decisions, human turns) to a per-client SQLite log with a SHA-256 hash chain — every record is cryptographically linked to the previous one
- Optionally notarises batches with a Merkle root + Ed25519 signature (paid tier) — external auditors can verify without contacting kajaril
- Exports all events for a data subject as NDJSON on demand (GDPR Art. 20 portability)
- Ships a Claude Code skill that runs 8 GDPR/AI-Act axes against any event store

## MCP endpoint

```
https://audit-event.kajaril.com/mcp
```

JSON-RPC 2.0 over HTTPS, authenticated via Cloudflare Access. Contact [studio@kajaril.com](mailto:studio@kajaril.com) for a service token.

## Tools

| Tool | Description |
|---|---|
| `record_event` | Write one audit event. Returns `{ id, chain_hash }`. |
| `verify_chain` | Recompute `chain_hash` for a range of events. Returns verified count and broken entries. |
| `query_events` | Filter by session, agent, event type, or date range. `input_hash` is never returned. |
| `export_dossier` | Export all events for a `subjectId` as NDJSON (GDPR Art. 20). Returns a 1-hour download URL. |

## Quick start

Record an event:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "record_event",
    "arguments": {
      "eventType": "tool.call",
      "purpose": "User requested flight search via travel assistant",
      "sessionId": "550e8400-e29b-41d4-a716-446655440000",
      "input": { "tool": "search_flights", "origin": "LHR", "dest": "JFK" },
      "lawfulBasis": "contract",
      "subjectId": "user-8821"
    }
  }
}
```

Verify the chain:

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
  "params": { "name": "verify_chain", "arguments": { "limit": 100 } } }
```

Export a data subject's records:

```json
{ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "export_dossier", "arguments": { "subjectId": "user-8821" } } }
```

## How it works

### Hash chain

Every event commits to all events before it. The chain is recomputable from first principles:

```
input_hash_slot = input_hash ?? input_hash_omitted_reason
chain_hash      = SHA-256(id + "|" + event_type + "|" + input_hash_slot + "|" + prev_hash)
```

When a caller supplies `inputHashOmittedReason` instead of `input`, the reason string enters the chain — the omission itself is tamper-evident.

### Merkle notary (paid tier)

Every 15 minutes (or at 1,000 pending events), the notary Worker:

1. Collects `{ id, chain_hash }` pairs from pending records
2. Sorts them by id and builds a SHA-256 binary Merkle tree
3. Signs the root with Ed25519
4. Writes `merkle_root` + `notary_sig` back to each record

The notary public key is published at `/.well-known/notary-pubkey`. Any auditor can verify signatures offline without contacting kajaril. The notary never receives `input_hash`, `payload_ref`, or any payload content.

### Privacy design

- `input` is hashed locally; the raw value is not stored unless an R2 bucket is explicitly bound
- `input_hash` is excluded from all `query_events` and `export_dossier` responses
- `payload_ref` is never returned to callers — enforced at every handler boundary
- An empty `export_dossier` result (`eventCount: 0`) is valid GDPR evidence that no data exists for a subject

## Event types

```
tool.call | tool.result | decision.made |
human.turn | memory.read | memory.write | error.raised
```

## Lawful basis (GDPR Art. 6)

```
legitimate_interest | contract | legal_obligation |
vital_interest | public_task | consent
```

Provide `lawfulBasis` for any event that processes personal data. Omit it for events that do not.

## Tiers

| Capability | Free | Paid |
|---|---|---|
| Hash-chained event writes | yes | yes |
| `verify_chain` | yes | yes |
| `export_dossier` (GDPR Art. 20) | yes | yes |
| R2 payload storage | optional | optional |
| Merkle root + Ed25519 notarisation | — | yes |
| compliance-audit axis 6 (notary coverage) | skipped | evaluated |

## compliance-audit skill

`skills/compliance-audit/SKILL.md` is a Claude Code skill that runs 8 GDPR/AI-Act compliance axes against any event store. Copy it into your workspace:

```sh
cp -r node_modules/@kajaril/audit-event-mcp/skills/compliance-audit .claude/skills/
```

Axes:

1. Lawful basis present — GDPR Art. 5–6
2. Purpose specificity — GDPR Art. 5(1)(b)
3. Subject linkage on `human.turn` events
4. Retention bounded (≤ 730 days)
5. Chain integrity — 10% sample recompute
6. Notary coverage ≥ 95% (paid tier only)
7. High-risk event completeness — AI Act Art. 12–13
8. Data minimisation signal — `payload_ref` fraction

Each axis produces `pass | fail | warn` with an evidence snippet. Output is JSON + a markdown summary block.

## Self-hosted deployment

### Prerequisites

- Cloudflare account with Workers and Durable Objects enabled
- `wrangler` CLI authenticated

### Steps

```sh
# 1. Create R2 bucket
wrangler r2 bucket create audit-payloads

# 2. Set notary signing key (paid tier)
wrangler secret put NOTARY_PRIVATE_KEY --config wrangler.notary.jsonc
# Value: hex-encoded Ed25519 private key — never committed to source

# 3. Deploy Workers
wrangler deploy
wrangler deploy --config wrangler.notary.jsonc

# 4. Add audit-event.kajaril.com as a CF Access Self-hosted Application
# Issue one service token per client with custom.client_id claim

# 5. Onboard a client
npx tsx src/scripts/onboard-client.ts --client-id acme-crm --tier free --region eu

# 6. Verify
curl https://audit-event.kajaril.com/health
```

Never run `wrangler deploy` from a dirty working tree. The deployed code must match git HEAD.

## Development

```sh
npm install
npm test          # 81 tests (node:sqlite adapter, no cloudflare/vitest-pool-workers)
npm run typecheck
npm run lint
```

## License

MIT. Copyright © 2026 Kajaril Ltd.
