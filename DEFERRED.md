# DEFERRED — temptations parked during the build week

v1 scope is locked (witness draft §5). Anything that felt necessary mid-build but is not on
the v1 list lands here with enough context to pick it up cold. Reordering happens after buyer
conversations, not before.

## Webhook delivery retries / witnessed-event outbox (Day 2; scope widened Day 4)

v1 sends the decision webhook once, fire-and-forget, and emits chain events with a single
synchronous `/record` call. If the DO refuses the `approval.decided` record or the customer's
endpoint is down, we log loudly and move on — the decision itself is already committed and
polling still resolves the approval. The robust version is an outbox in the tenant DO drained
by alarms (retry webhook deliveries with backoff; re-attempt failed chain-event emission).
Do not build before someone actually loses a delivery they cared about.

Day 4 added two more single-attempt sends in the same posture: the Telegram approval card
(failure degrades to the email rung — `notifications.telegram: "failed"` plus an immediate
escalation) and the escalation email itself (the DO marks the escalations row
`result: "failed"` and never retries). If retries ever get built, all three belong in the one
outbox — no channel gets its own bespoke retry loop.

## Channel management surface (Day 4)

v1 channel config is write-only: connecting Telegram again replaces the bound chat,
POST /channels/email overwrites the address, and nothing lists or disconnects. The moment a
tenant asks "which chat is this bound to?" the shape is GET /channels + DELETE per channel —
bundle it with the admin surface (same v1.5 bundle as per-tenant webhook-secret rotation).

## Multi-approver / multi-chat per tenant (Day 4)

One Telegram chat and one approver address per tenant, by design — the v1 buyer IS the
approver. Group chats already work (bind the group; anyone in it can decide, responder_id
records who), but real multi-approver semantics (quorum, delegation, per-agent routing) are
a v1.5 verbs question (witness draft D5), not a channels question. Park until a buyer
describes their team.

## Real ack signals for the escalation window (Day 4)

"Unacked after 10 min" is implemented as "undecided after 10 min" — Telegram delivery is
treated as reaching a human. Telegram offers no read receipts for bots, so a truer ack would
need an explicit "I'm looking at it" button (an extended-pending state ≈ snooze, reserved in
D5 as a v1.5 verb). A redundant email to someone already deciding costs nothing; do not build
ack plumbing before someone complains about the noise.

## Recorder attestation source for approval.* events (v1.5 design question)

v1 reserves `approval.requested` / `approval.decided` on the public `record_event` surface so
agents cannot fabricate decision evidence — only the witness emits them. The v1.5 recorders
("keep your approval flow, we make it provable") will need to record approvals that happened
inside LangGraph/n8n/etc. Those must NOT reuse the reserved types silently: they need an
attestation-source distinction (witness-attested vs recorder-attested) in the event, or
separate `approval.recorded.*` types. Decide when the first recorder is built, not before.

## Per-tenant webhook secret rotation (v1.5)

D9 derives webhook secrets via HKDF(master, clientId): rotating the master rotates every
tenant at once. A per-tenant rotation surface needs key versioning in the derivation info
string (`kajaril-webhook-v2:…` or `…:v<N>`) plus a way to signal the active version to the
customer. Needs the admin surface anyway — bundle with it.

## M2M access-token revocation before expiry (Day 3)

Access tokens are stateless HS256 JWTs: nothing exists to revoke one against, and the 1-hour
TTL bounds the exposure. Rotating the client secret stops NEW tokens immediately; rotating
M2M_TOKEN_SIGNING_SECRET kills every outstanding token across all tenants at once. If a
customer ever needs surgical revocation (leaked token, fired contractor), the shape is a jti
denylist in the tenant DO checked on Bearer auth — one read per request. Do not build it
before someone asks; the two rotation levers cover the realistic cases.

## Negative-cache for token-endpoint DO instantiation (Day 3)

POST /oauth/token is the one place an unverified client_id reaches idFromName — a credential
cannot be checked without reading the claimed tenant's stored hash, so garbage client_ids
instantiate empty DOs (constructor runs CREATE TABLE; pennies of storage). Shape checks plus
the per-IP and per-client rate caps (30/min each) bound the damage. If abuse shows up in
observability, add a KV negative-cache or move the credential index out of the DO; not before.

## Rate limiting on the go worker's decide endpoint

Approval creation is rate-limited per tenant (30/min). The public decide POST is gated by the
HMAC link token, so abuse requires a valid link; per-IP limits on `/a/:token/decide` would be
belt-and-suspenders. Add only if abuse shows up in observability.
