# CLAUDE.md — @kajaril/audit-event-mcp

This file is the constitution for Claude Code working in this repo. Read it before any non-trivial change.

---

## What this repo is

`@kajaril/audit-event-mcp` is agent steward infrastructure: a hash-chained audit log backed by a Cloudflare Durable Object, with optional Merkle notarisation and a GDPR/AI-Act compliance skill. MIT-licensed.

This is a governance product. Every decision in the codebase is on the record. DPO buyers and regulators will read this code.

## Required reading before structural changes

1. `.context/kajaril-source-of-truth.md` — strategy, stack, roadmap
2. `.context/kajaril-decisions-addendum-wk0.md` — entity-level locked decisions
3. `.context/audit-event-mcp-build-plan.md` — this repo's build plan + all locked decisions

These live in the workspace `.context/` folder, not in this repo. Deviating from any locked decision requires stopping, asking, and recording the new decision before code changes.

## Locked decisions

1. **Two Workers** — `wrangler.jsonc` (main) + `wrangler.notary.jsonc` (notary). They are independent deployments. Never merge them into one config.
2. **DO SQLite, not D1** — `state.storage.sql.exec()` is the API. Never add a D1 binding to this repo.
3. **`new_sqlite_classes`, not `new_classes`** — Wrangler migration tag for SQLite-enabled DOs. Do not change.
4. **Shared R2 bucket** — one `audit-payloads` bucket, per-client isolation via `{client_id}/{event_id}` key prefix in `do.ts`. Never per-client buckets.
5. **CF Access JWT routing** — Worker reads `payload.custom.client_id` from the CF Access JWT; DO name = `audit-do-{client_id}`. Never use URL segments for client routing.
6. **Hash chain algorithm** — locked. `input_hash_slot = input_hash ?? input_hash_omitted_reason`. Never empty string. `chain_hash = SHA-256(id + "|" + event_type + "|" + input_hash_slot + "|" + (prev_hash ?? ""))`. Do not change without a new decision entry.
7. **Six MCP tools exactly** — `record_event`, `verify_chain`, `query_events`, `export_dossier`, `request_approval`, `check_approval`. Was four; widened by the witness integration decision (kajaril-witness-integration-draft.md §3, Day 3, 2026-06-12). Do not add tools without a new decision.
8. **`payload_ref` never returned** — tool responses never include `payload_ref` keys or raw payload content. This is a privacy invariant.
9. **`NOTARY_PRIVATE_KEY` is a Workers Secret** — set via `wrangler secret put`, never in source, comments, or commits.
10. **`migrations/0001_init.sql` is applied by `do.ts`** — the DO constructor calls `state.storage.sql.exec(SCHEMA_SQL)`. Never apply via `wrangler d1 migrations apply`.
11. **License + metadata** — MIT. `package.json` author, repository, homepage, bugs are locked.

## Deploy safety rule

**Never run `wrangler deploy` without a clean `git status` first.**

Deploying from a dirty working tree means the deployed code is not in git — recovery requires a reconstruction PR. sovereignty-scan-mcp violated this and required recovery PR #18.

Before any deploy:
```sh
git status   # must show "nothing to commit, working tree clean"
wrangler deploy
```

## Coding conventions

- **TypeScript** strict mode (`"strict": true`, `"noUncheckedIndexedAccess": true`)
- **Biome 2.x** for formatting and linting. Pre-commit hook enforces. No exceptions.
- **Hono** for HTTP routing. Named exports only — no default exports in `src/`.
- **`async/await` only** — no `.then()` chains.
- **No comments that restate what the code does.** Only comment WHY something is non-obvious.
- **Error handling**: throw typed errors, catch at handler boundary, return structured error. Never silent catch.
- **Zod v4** — `AuditEventInputSchema` with XOR validation (input XOR inputHashOmittedReason). Never bypass validation.

## Test discipline

- Pre-commit hook blocks `.only()` in test files.
- No `.skip` without an attached `// TODO(reason, owner, deadline)` comment.
- `test/chain.test.ts` covers all hash chain invariants — do not weaken these tests.
- Tests run in Node.js environment (`vitest.config.ts` `environment: "node"`). No `@cloudflare/vitest-pool-workers`.
- `test/node-sqlite.d.ts` provides `node:sqlite` types — add to it if the stable API grows.

## Commit and PR conventions

- Signed commits required on `main`. YubiKey-backed.
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.
- No Co-Authored-By or "Generated with" lines in commit messages or PR descriptions.
- One concern per PR.

## Secrets handling

**Where secrets live:**
- `NOTARY_PRIVATE_KEY`: Cloudflare Workers Secret, set via `wrangler secret put NOTARY_PRIVATE_KEY --config wrangler.notary.jsonc`. Hex-encoded Ed25519 private key. Never in source.
- CF Access service tokens per client: CF dashboard only. Never in this repo.
- Local dev: `.dev.vars` at repo root, gitignored. Never committed.

**Never appears in:**
- Source, tests, comments, commit messages, PR descriptions, docs, issue descriptions, logs.

## Filesystem boundaries

Do not read or write outside the repo root without an explicit ask.

**Inside the repo, never modify:**
- `.env`, `.env.*`, `.dev.vars` — secrets
- `.wrangler/` — local state
- `node_modules/`, `dist/`, `build/`
- `migrations/0001_init.sql` after first prod apply — additive only via `0002_*.sql`

## Repo state

| Milestone | Status | Notes |
|---|---|---|
| Scaffolding + hash chain (M8 foundation) | _in progress_ | 2026-05-15 |
| Witness Day 1: approvals in AuditDO, HMAC link tokens, go.kajaril.com worker + approve page | done | 2026-06-11 — see kajaril-witness-integration-draft.md §3; not yet deployed |
| Witness Day 2: approval.requested/decided chain events, action-payload hashing (D6), signed decision webhook (D9), per-channel TTL, rate limiter | done | 2026-06-12 — webhook-secret design recorded as D9 in the draft; not yet deployed |
| Witness Day 3: M2M client-credentials auth (hand-rolled, D2/D10), tool dispatch 4→6, REST approval surface, approval_url minting | done | 2026-06-12 — credential-storage design recorded as D10 in the draft; workers-oauth-provider pinned 0.7.2 exact (PR #30, founder-approved security-fix override of the 2-week quarantine); browser-flow wiring pending; not yet deployed |
| Witness Day 4: CF Access aud pin; channel ladder (D4) — Telegram cards + callbacks + deny-with-reason, one-time connect deep links, Resend email escalation via DO alarm, CHANNELS_KV routing config | done | 2026-06-12 — all Telegram/Resend coverage synthetic, live E2E is deploy day; deploy-day steps in both wrangler configs (KV namespace, 3 new secrets, bot username var, CF_ACCESS_APP_AUD, setWebhook); browser-flow endpoint-ownership decision still pending; not yet deployed |

Update this table as milestones close.

## When in doubt

Stop. Ask. Read the build plan. Then ask again.
