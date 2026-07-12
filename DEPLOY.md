# DEPLOY.md — first production deploy (deploy day)

The complete sequence for taking the witness integration live. Written Day 5 (2026-06-13)
from the deploy-day notes in `wrangler.jsonc` / `wrangler.go.jsonc` / `wrangler.notary.jsonc`.
Secret **names** only — every value comes from founder cold storage. Nothing here is
deployed without the founder's explicit go-ahead.

Three workers, deployed in dependency order:

| # | Worker | Config | Domain |
|---|---|---|---|
| 1 | `audit-event-notary` | `wrangler.notary.jsonc` | audit-event-notary.kajaril.com |
| 2 | `audit-event-mcp` (gated) | `wrangler.jsonc` | audit-event.kajaril.com |
| 3 | `go-kajaril` (public) | `wrangler.go.jsonc` | go.kajaril.com |

Order matters: 2 has a service binding to 1 (`NOTARY`); 3 has service bindings to 2
(`ApprovalInternal`, `DossierInternal`) and to 1 (`NOTARY`).

---

## 0. Preconditions

```sh
cd audit-event-mcp
git checkout main && git pull
git status            # MUST print "nothing to commit, working tree clean" (repo rule)
npx wrangler whoami   # confirm this is the kajaril account, not a personal/test one
npm test              # suite green (327)
```

CI on `main` is green. The kajaril.com zone is on this Cloudflare account (custom domains
below auto-create DNS records + certs on deploy — no manual DNS steps).

**Have ready before §7:** a `CF_API_TOKEN` with `Workers Scripts:Edit` permission —
`onboard-client.ts` (the §7 onboarding step) reads it from the shell env and errors out if unset.

---

## 1. Platform resources (create once)

```sh
# R2 bucket (shared; per-client isolation is key-prefix based — locked decision).
# EU-jurisdiction pinned (locked decision 12, 2026-07-10) — already created; this
# line is here for reference, not a step to re-run.
npx wrangler r2 bucket create audit-payloads-eu --jurisdiction eu

# KV namespaces
npx wrangler kv namespace create CHANNELS_KV     # → prints id A
npx wrangler kv namespace create OAUTH_KV        # → prints id B
```

Now edit the configs (the bindings are pre-written as comments):

- `wrangler.jsonc` → uncomment `kv_namespaces`, fill **id A** for `CHANNELS_KV` and
  **id B** for `OAUTH_KV`.
- `wrangler.go.jsonc` → uncomment `kv_namespaces`, fill **id A** for `CHANNELS_KV`
  (the **same** namespace as the gated worker — the Telegram webhook resolves
  chat → tenant bindings written by the gated worker). The go worker gets **no** OAUTH_KV.

```sh
git add wrangler.jsonc wrangler.go.jsonc
git commit -m "chore(deploy): bind CHANNELS_KV + OAUTH_KV namespace ids"
git push   # deploy only from a clean tree that matches origin/main
```

The `AUDIT_DO` Durable Object namespace and its SQLite migration (`new_sqlite_classes`)
apply implicitly on the first `wrangler deploy` — no CLI step.

---

## 2. Secrets (names only — values from cold storage)

`wrangler secret put` prompts on stdin; paste the value, never put it in a command line
or shell history.

**Notary** — ⚠️ **already LIVE in production** (verified 2026-06-26: `audit-event-notary.kajaril.com/.well-known/notary-pubkey` returns 200) and **unchanged by the witness work**. **Do NOT `put` a new `NOTARY_PRIVATE_KEY` value** — every existing notarized event and `/verify` depends on the current key; rotating it invalidates all prior signatures. Re-putting the *same* value is harmless but unnecessary, so skip this step unless you have confirmed the secret is actually missing:

```sh
npx wrangler secret put NOTARY_PRIVATE_KEY --config wrangler.notary.jsonc
# hex-encoded Ed25519 private key
```

**Gated worker** (`wrangler.jsonc`) — five:

```sh
npx wrangler secret put WEBHOOK_SIGNING_SECRET      # D9 master — high-entropy random
npx wrangler secret put APPROVAL_TOKEN_SECRET       # D3 link HMAC — SAME value as go worker's
npx wrangler secret put M2M_TOKEN_SIGNING_SECRET    # D10 token signing — high-entropy random
npx wrangler secret put TELEGRAM_BOT_TOKEN          # @BotFather token — SAME value as go worker's
npx wrangler secret put RESEND_API_KEY              # Resend key (email fallback)
```

**Go worker** (`wrangler.go.jsonc`) — three:

```sh
npx wrangler secret put APPROVAL_TOKEN_SECRET   --config wrangler.go.jsonc  # same value as above
npx wrangler secret put TELEGRAM_BOT_TOKEN      --config wrangler.go.jsonc  # same value as above
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET --config wrangler.go.jsonc  # OUR random value, used in step 5
```

Day-0 cautions that bite here:
- The bot token must come from @BotFather / cold storage — CF secrets are write-only,
  it cannot be read back from gvnr's deployment.
- The Resend key must be verified **from a worker** (step 7) — inbox send/receive working
  ≠ API access working.

---

## 3. Vars (gated worker)

`CF_ACCESS_TEAM_DOMAIN` is already committed. Two more go into `wrangler.jsonc` `vars`
(commit, since they are not secrets):

- `TELEGRAM_BOT_USERNAME` — the bot's public @username (no `@`). While fetching it,
  do the Day-0 check: the bot's public name/about must be kajaril-appropriate
  (it started life as a gvnr ops bot — rename in @BotFather if needed).
- `CF_ACCESS_APP_AUD` — from step 4 below.

Optional: `APPROVAL_LINK_BASE_URL` — leave unset in production (defaults to
`https://go.kajaril.com`; it is the base for both approval links and dossier links).

---

## 4. Cloudflare Access application

**Confirmed 2026-06-26 — the Access app already EXISTS** and currently covers the whole
hostname (`/health` returns 403 with `cf-access-aud:
6ad00a6ef11389a5421f901175cd20901538f1b387049cec1e7e1310dc8f3557`). So this step is **adjust
the existing app, not create one**, and that AUD is almost certainly the `CF_ACCESS_APP_AUD`
value — confirm in the dashboard it is the intended app. The path re-scope below (exposing
`/health` plus the Bearer lanes) is **mandatory**: §7's `/health → 200` and
`grant_type=bogus → 400` will FAIL until it is done.

Zero Trust dashboard → Access → Applications → add (or confirm) a **self-hosted** app for
`audit-event.kajaril.com`. Then copy its **AUD tag** (Overview tab) into
`CF_ACCESS_APP_AUD` (step 3) — the worker pins JWT verification to exactly this app and
fails closed (503) without it.

What must be true:

1. **`/oauth/authorize` must be covered** with an **Allow** policy listing operator
   emails (founder + pilot tenant admins). This is the human-login fence for OAuth
   consent — without it, nobody can approve a browser-flow grant (the page itself
   refuses unauthenticated requests, so a gap here fails safe but breaks `claude mcp add`).
2. **Service Auth** policy on the same app for the B2B service-token lane
   (`onboard-client.ts` step-5/6 connectivity + credential bootstrap go through it).
3. **The Bearer-lane paths must NOT be blocked by Access**: `/oauth/token`,
   `/oauth/register`, `/.well-known/*`, and `/mcp` + `/approvals` for self-serve Bearer
   clients. Any path the Access app covers is unreachable for plain-Bearer callers, so
   scope the app to the paths that genuinely need Access (at minimum `/oauth/authorize`;
   plus the paths B2B service-token tenants call, while there are no Bearer-only tenants
   sharing them). **This is the one real topology decision on deploy day** — pick based
   on the pilot mix; the worker fails closed in either direction, and the probes in
   step 7 reveal a wrong scoping immediately.

Both policy types on one app share one AUD, which is what the single
`CF_ACCESS_APP_AUD` pin expects.

---

## 5. Deploy + Telegram webhook

```sh
git status   # clean tree, again — vars/KV edits from steps 1+3 must be committed
npx wrangler deploy --config wrangler.notary.jsonc   # 1 — likely a no-op: notary already live + unchanged. Confirm via 'wrangler deployments list --config wrangler.notary.jsonc' rather than redeploy blind
npx wrangler deploy                                  # 2 (gated; migration applies here)
npx wrangler deploy --config wrangler.go.jsonc       # 3 — MUST follow step 2's redeploy: go binds the gated worker's witness entrypoints (ApprovalInternal/DossierInternal), absent on a pre-witness base worker
```

Register the Telegram webhook (after step 2+3 secrets and the go deploy):

```sh
curl -s "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -d url=https://go.kajaril.com/tg/webhook \
  -d secret_token=<TELEGRAM_WEBHOOK_SECRET> \
  -d 'allowed_updates=["message","callback_query"]'

curl -s "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/getWebhookInfo"
# expect: url set, pending_update_count 0, no last_error_message
```

---

## 6. DNS / custom domains

`custom_domain: true` routes create the DNS records and certificates automatically at
deploy. Verify in dash (Workers & Pages → each worker → Domains): all three hostnames
active, certs issued. `workers_dev` is `false` on the two app workers — confirm the
`*.workers.dev` URLs are disabled (step 7 probes this too).

---

## 7. Smoke checks (in order; stop on first failure)

```sh
# liveness
curl -s https://audit-event.kajaril.com/health           # {"status":"ok",...}
curl -s https://go.kajaril.com/health                    # {"status":"ok","product":"go-kajaril",...}
curl -s https://audit-event-notary.kajaril.com/.well-known/notary-pubkey   # Ed25519 + publicKey hex
curl -s https://go.kajaril.com/.well-known/notary-pubkey                   # same key, via proxy

# the gated worker is gated
curl -s -o /dev/null -w '%{http_code}\n' https://audit-event-mcp.<acct>.workers.dev/health   # NOT 200 (workers_dev off)
curl -s -X POST https://audit-event.kajaril.com/mcp -d '{}'   # 401 (no credentials)

# OAuth surfaces (D11)
curl -s https://audit-event.kajaril.com/.well-known/oauth-authorization-server
#   token_endpoint .../oauth/token; grant_types authorization_code, refresh_token, client_credentials
curl -s -X POST https://audit-event.kajaril.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=bogus'
#   400 {"error":"unsupported_grant_type",...}  ← proves Access is NOT intercepting the token endpoint
curl -s -o /dev/null -w '%{http_code}\n' https://audit-event.kajaril.com/oauth/authorize
#   302 to the Access login ← proves Access IS intercepting consent

# first tenant, full loop (uses the founder's phone)
# prerequisite: CF_API_TOKEN (Workers Scripts:Edit) exported in this shell
npx tsx src/scripts/onboard-client.ts --client-id pilot-1 --tier free --region eu
#   then follow its printed steps: service token + custom.client_id claim,
#   /credentials/rotate bootstrap (admin + agent), keep the one-time secrets.
# mint a token:
curl -s https://audit-event.kajaril.com/oauth/token -u "pilot-1:<agent secret>" \
  -d grant_type=client_credentials -d scope=agent
# connect Telegram (admin token):
curl -s -X POST https://audit-event.kajaril.com/channels/telegram/connect \
  -H "Authorization: Bearer <admin token>"            # open the t.me link, press Start
# E2E approval: request → phone buzzes → tap Approve → poll shows approved + chainEvent
curl -s -X POST https://audit-event.kajaril.com/approvals \
  -H "Authorization: Bearer <agent token>" -H 'Content-Type: application/json' \
  -d '{"agentId":"smoke","sessionId":"smoke-1","actionSummary":"Deploy-day smoke approval","channels":["telegram"]}'
curl -s https://audit-event.kajaril.com/approvals/<id> -H "Authorization: Bearer <agent token>"

# email fallback (verifies the Resend key from a worker — Day-0 caution)
curl -s -X POST https://audit-event.kajaril.com/channels/email \
  -H "Authorization: Bearer <admin token>" -H 'Content-Type: application/json' \
  -d '{"address":"studio@kajaril.com"}'
#   then an approval with "channels":["email"] → mail arrives from approvals@send.kajaril.com

# evidence surfaces (THE demo)
#   record a couple of events with subjectId, export_dossier (admin), open the returned
#   go.kajaril.com/dossier/... URL → readable page renders → download evidence file →
#   drop it on https://go.kajaril.com/verify → green ticks, "Verified" verdict.

# browser OAuth flow (after the smoke above)
claude mcp add --transport http audit-event https://audit-event.kajaril.com/mcp
#   browser opens → Access SSO → consent page → Authorize → tools listed in Claude
```

The decision webhook can be smoke-checked with any request bin: pass `callbackUrl` on an
approval, verify the `X-Kajaril-Signature` header against the `webhookSecret` from the
response (scheme documented in README).

---

## 8. Rollback

Workers roll back independently; DO/KV/R2 data is never touched by a rollback.

```sh
npx wrangler deployments list [--config <cfg>]     # find the previous version
npx wrangler rollback [--config <cfg>]             # interactive; or --version-id <id>
```

- **go-kajaril** is stateless (routing KV only) — roll back freely.
- **audit-event-mcp**: rolling back past Day 1 of the witness work would deploy code
  that does not know the `approvals`/`credentials` tables — the tables are additive and
  harmless, but approval/auth surfaces vanish. Evidence (audit_events) is unaffected.
- **Telegram misbehaving**: stop callback traffic without any redeploy:
  `curl -s "https://api.telegram.org/bot<TOKEN>/deleteWebhook"`.
- **Secret compromise**: rotate via `wrangler secret put` (same names). Rotating
  `M2M_TOKEN_SIGNING_SECRET` invalidates all outstanding access tokens (clients
  re-auth within the hour); rotating `WEBHOOK_SIGNING_SECRET` rotates every tenant's
  webhook secret at once (customers self-heal from the next `request_approval`
  response); rotating `APPROVAL_TOKEN_SECRET` invalidates outstanding approval links
  (pending approvals still resolvable by polling).
- The kajaril.com site deploys separately (auto-deploy on push in its own repo) and is
  untouched by any of this.
