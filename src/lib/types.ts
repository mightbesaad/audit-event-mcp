// approval.* types are emitted by the worker layer only (D7); the public record_event
// surface rejects them. Reserved for v1.5: "approval.deferred", "approval.escalated".
export type EventType =
  | "tool.call"
  | "tool.result"
  | "decision.made"
  | "human.turn"
  | "memory.read"
  | "memory.write"
  | "error.raised"
  | "approval.requested"
  | "approval.decided";

export type LawfulBasis =
  | "legitimate_interest"
  | "contract"
  | "legal_obligation"
  | "vital_interest"
  | "public_task"
  | "consent";

export interface AuditLogConfig {
  agentId: string;
  doNamespace: DurableObjectNamespace;
  clientId: string;
  r2Bucket?: R2Bucket;
  defaultLawfulBasis?: LawfulBasis;
  defaultRetentionDays?: number;
}

export interface AuditEventInput {
  eventType: EventType;
  purpose: string;
  sessionId: string;
  input?: unknown;
  inputHashOmittedReason?: string;
  lawfulBasis?: LawfulBasis;
  subjectId?: string;
  retentionDays?: number;
  stripeCardId?: string;
  stripeAuthorizationId?: string;
}

export interface AuditEvent {
  id: string;
  agentId: string;
  sessionId: string;
  eventType: EventType;
  inputHash: string | null;
  inputHashOmittedReason: string | null;
  payloadRef: string | null;
  lawfulBasis: LawfulBasis | null;
  purpose: string;
  subjectId: string | null;
  retentionDays: number;
  prevHash: string | null;
  chainHash: string;
  merkleRoot: string | null;
  notarySig: string | null;
  stripeCardId: string | null;
  stripeAuthorizationId: string | null;
  createdAt: string;
}

export interface RecordResult {
  id: string;
  chainHash: string;
}

export interface VerifyResult {
  verified: number;
  broken: { id: string; expected: string; actual: string }[];
}

export interface DossierResult {
  url: string;
  expiresAt: string;
  eventCount: number;
}

export interface Env {
  AUDIT_DO: DurableObjectNamespace;
  AUDIT_PAYLOADS?: R2Bucket;
  NOTARY?: Fetcher;
  CF_ACCESS_TEAM_DOMAIN?: string;
  // AUD tag of the one CF Access application protecting this worker (Day-4 pin, Day-3
  // review): without it, a JWT minted for ANY Access app on the team domain verifies here,
  // and that JWT now bootstraps admin credentials. Unset → CF Access auth fails closed (503),
  // same as a missing team domain.
  CF_ACCESS_APP_AUD?: string;
  // Cloudflare ratelimit binding (wrangler.jsonc "unsafe"): 30 approval creations/min per
  // tenant, gvnr's donor pattern. Optional so Node tests and self-hosters without the
  // binding run unlimited — absence fails open by design (it protects shared capacity,
  // not tenant data).
  APPROVAL_RATE_LIMITER?: RateLimit;
  // Master for per-tenant webhook signing secrets (D9), a Workers Secret. Unset → decision
  // webhooks are not sent and request_approval returns webhookSecret: null. Fail closed:
  // an unsigned webhook is forgeable and never leaves the worker.
  WEBHOOK_SIGNING_SECRET?: string;
  // HMAC key for the approval link tokens (D3), a Workers Secret bound to BOTH workers with
  // the same value: the go worker verifies links, this worker mints them so request_approval
  // can return approval_url. Unset → approvalUrl: null (the approval still works via polling).
  APPROVAL_TOKEN_SECRET?: string;
  // Where approval links point. Defaults to the production go worker; self-hosters override.
  APPROVAL_LINK_BASE_URL?: string;
  // Signing key for M2M access tokens (D2), a Workers Secret. Unset → /oauth/token and
  // Bearer auth fail closed (503): a token we cannot verify must never select a tenant.
  M2M_TOKEN_SIGNING_SECRET?: string;
  // Storage for the browser OAuth flow (D11): workers-oauth-provider keeps DCR'd clients,
  // grants, and token hashes here. Routing/auth state only, never evidence. Unset → the
  // authorization_code / refresh_token branch of /oauth/token, /oauth/register, and
  // browser-token Bearer auth all fail closed (503); client_credentials is unaffected.
  // Deploy day: create-and-bind alongside CHANNELS_KV (D11 condition 6).
  OAUTH_KV?: KVNamespace;
  // Channel routing config (D4): connect codes, telegram chat bindings, approver email.
  // Bound to BOTH workers — the go worker's Telegram webhook resolves chat → tenant here.
  // Mutable routing state only, never evidence: nothing in this KV is witnessed material,
  // and losing it disconnects channels without touching any chain. Unset → channel sends
  // are skipped; approvals still work via approval_url + polling.
  CHANNELS_KV?: KVNamespace;
  // Telegram bot credentials (D4), Workers Secrets. The token sends approval cards from
  // this worker; the go worker holds the same token to answer callbacks. The username is
  // a plain var (it is public — it appears in every t.me deep link).
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_BOT_USERNAME?: string;
  // Resend API key (D4 email fallback), a Workers Secret. The DO reads it when an
  // escalation alarm fires. Unset → email escalations are recorded as skipped.
  RESEND_API_KEY?: string;
}

// Env for the go.kajaril.com public worker (wrangler.go.jsonc / src/go.ts).
// AUDIT is the service binding to the ApprovalInternal entrypoint in src/main.ts —
// typed structurally so tests can substitute a plain mock.
export interface GoEnv {
  AUDIT: import("@/lib/approval").ApprovalInternalClient;
  // Dossier reads (D1, Day 5): the DossierInternal entrypoint in src/main.ts — a second,
  // separately-named capability; ApprovalInternal stays get/decide only. Unset → dossier
  // pages fail closed (503).
  DOSSIER?: import("@/lib/dossier").DossierInternalClient;
  // Service binding to the notary worker: /verify fetches the notary public key
  // same-origin through this proxy, so the notary needs no CORS and stays untouched.
  // Unset → /.well-known/notary-pubkey reports 503 (the /verify page degrades to
  // "unverifiable", never to a false verdict).
  NOTARY?: Fetcher;
  APPROVAL_TOKEN_SECRET?: string;
  // Telegram webhook surface (D4). The webhook secret is OUR value, registered with
  // setWebhook and echoed back by Telegram in X-Telegram-Bot-Api-Secret-Token — the only
  // proof an update really came from Telegram. Any of the three unset → /tg/webhook
  // fails closed (503).
  CHANNELS_KV?: KVNamespace;
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_WEBHOOK_SECRET?: string;
}
