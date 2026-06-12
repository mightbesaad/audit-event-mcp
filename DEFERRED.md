# DEFERRED — temptations parked during the build week

v1 scope is locked (witness draft §5). Anything that felt necessary mid-build but is not on
the v1 list lands here with enough context to pick it up cold. Reordering happens after buyer
conversations, not before.

## Webhook delivery retries / witnessed-event outbox (Day 2)

v1 sends the decision webhook once, fire-and-forget, and emits chain events with a single
synchronous `/record` call. If the DO refuses the `approval.decided` record or the customer's
endpoint is down, we log loudly and move on — the decision itself is already committed and
polling still resolves the approval. The robust version is an outbox in the tenant DO drained
by alarms (retry webhook deliveries with backoff; re-attempt failed chain-event emission).
Do not build before someone actually loses a delivery they cared about.

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

## Rate limiting on the go worker's decide endpoint

Approval creation is rate-limited per tenant (30/min). The public decide POST is gated by the
HMAC link token, so abuse requires a valid link; per-IP limits on `/a/:token/decide` would be
belt-and-suspenders. Add only if abuse shows up in observability.
