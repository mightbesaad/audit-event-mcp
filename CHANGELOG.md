# Changelog

All notable changes are recorded here.
Code changes follow [semantic versioning](https://semver.org); data updates increment the minor version.

---

## [Unreleased]

Witness integration, build week 2026-06-11 → 2026-06-13 (not yet deployed):

- Approvals as witnessed evidence: `request_approval` / `check_approval` tools + REST,
  approval state in the tenant DO, `approval.requested` / `approval.decided` chain events,
  HMAC-signed approval links served by the public go.kajaril.com worker
- Channel ladder: Telegram approval cards with deny-with-reason, email escalation fallback
  (Resend) via DO alarm, per-channel TTL defaults, signed decision webhooks (Stripe-shaped
  `t=,v1=` signatures, HKDF per-tenant secrets)
- Auth: OAuth client-credentials (hand-rolled HS256, hashed-at-rest secrets, agent/admin
  scopes) and browser OAuth (workers-oauth-provider 0.7.2 — DCR, PKCE S256 consent,
  refresh tokens) behind one `/oauth/token` routed by grant_type; CF Access JWTs pinned to
  the application AUD
- Evidence surfaces: human-readable HTML dossier + raw JSONL on go.kajaril.com, public
  /verify page with fully client-side chain + Ed25519 notary verification; dossier export
  now carries the chain preimage (digests only — `payload_ref` never leaves)
- DEPLOY.md: the full first-deploy runbook

Initial build — scaffolding, hash chain, DO skeleton.
