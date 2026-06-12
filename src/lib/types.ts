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
  // Cloudflare ratelimit binding (wrangler.jsonc "unsafe"): 30 approval creations/min per
  // tenant, gvnr's donor pattern. Optional so Node tests and self-hosters without the
  // binding run unlimited — absence fails open by design (it protects shared capacity,
  // not tenant data).
  APPROVAL_RATE_LIMITER?: RateLimit;
  // Master for per-tenant webhook signing secrets (D9), a Workers Secret. Unset → decision
  // webhooks are not sent and request_approval returns webhookSecret: null. Fail closed:
  // an unsigned webhook is forgeable and never leaves the worker.
  WEBHOOK_SIGNING_SECRET?: string;
}

// Env for the go.kajaril.com public worker (wrangler.go.jsonc / src/go.ts).
// AUDIT is the service binding to the ApprovalInternal entrypoint in src/main.ts —
// typed structurally so tests can substitute a plain mock.
export interface GoEnv {
  AUDIT: import("@/lib/approval").ApprovalInternalClient;
  APPROVAL_TOKEN_SECRET?: string;
}
