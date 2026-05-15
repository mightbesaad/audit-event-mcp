# Security Policy

## Scope

Report vulnerabilities in:

- **Worker code** — logic errors, injection, authentication bypass
- **CF Access JWT validation** — token forgery, claim manipulation
- **Hash chain integrity** — algorithm weaknesses, collision exploits
- **Notary signing** — Ed25519 key handling, signature bypass
- **API endpoint** — unexpected data exposure, request smuggling

Out of scope: rate limit bypass attempts, DoS, issues in third-party dependencies (report those upstream).

## Reporting

Email **studio@kajaril.com** with subject: `[SECURITY] audit-event-mcp — <short description>`

Include:
- What the issue is and where it occurs
- Steps to reproduce
- Impact in your assessment

Please do not open a public GitHub issue for security vulnerabilities.

## Response

- **Acknowledge**: within 48 hours
- **Confirm and patch**: within 7 days for confirmed issues
- **Disclosure**: coordinated — we will notify you before any public disclosure

## Key rotation

If the `NOTARY_PRIVATE_KEY` is suspected to be compromised, rotate it immediately via `wrangler secret put`.
Old signatures remain verifiable against the previously published public key at `/.well-known/notary-pubkey`.
