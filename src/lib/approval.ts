// Approval domain: constants, wire types, and pure state helpers.
// Ported from gvnr src/lib/approval.ts (donor, read-only) with two deliberate changes:
//   - storage is the tenant AuditDO's SQLite, not KV (decision D3) — SQL lives in do.ts
//   - timestamps are ISO-8601 strings, matching audit_events, not epoch millis

export type ApprovalStatus = "pending" | "approved" | "denied" | "timeout";
export type ApprovalDecision = "approved" | "denied";

export const MIN_APPROVAL_TTL_SECONDS = 1; // anything shorter is pointless; permitted for short polling tests
export const MAX_APPROVAL_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days — covers async/email-only approvers
// 30 min assumes someone is notified instantly (telegram/push) or watching the approval_url.
// gvnr's 600s default was calibrated for a watching human — not ported (decision D4).
export const DEFAULT_APPROVAL_TTL_SECONDS = 30 * 60;
// Email is a fallback channel nobody stares at; 30 min would time out most real approvals (D4).
export const EMAIL_ONLY_APPROVAL_TTL_SECONDS = 4 * 60 * 60;

export function defaultTtlSeconds(channels: readonly string[]): number {
  const hasInstant = channels.includes("telegram") || channels.includes("push");
  const emailOnly = !hasInstant && channels.includes("email");
  return emailOnly ? EMAIL_ONLY_APPROVAL_TTL_SECONDS : DEFAULT_APPROVAL_TTL_SECONDS;
}
export const MAX_ACTION_SUMMARY_CHARS = 280;
export const MAX_AGENT_ID_CHARS = 128;
export const MAX_REASON_CHARS = 500;
export const MAX_ACTION_TOOL_CHARS = 128;
// Cap on the canonical JSON of action_payload: it is stored per approval, rendered on the
// approve page, and (Day 4) sent to Telegram, whose message limit is 4096 chars. Bigger
// payloads belong behind the hash, not in the human's card.
export const MAX_ACTION_PAYLOAD_CHARS = 4096;
// Our ids are 22 chars (16 bytes base64url). Allow up to 64 for forward-compat.
export const MAX_APPROVAL_ID_CHARS = 64;
const APPROVAL_ID_RE = /^[A-Za-z0-9_-]+$/;

// client_id also becomes part of a DO name — same conservative charset as approval ids.
export const MAX_CLIENT_ID_CHARS = 128;
const CLIENT_ID_RE = /^[A-Za-z0-9_-]+$/;

export function isValidApprovalIdShape(id: string): boolean {
  return (
    typeof id === "string" &&
    id.length > 0 &&
    id.length <= MAX_APPROVAL_ID_CHARS &&
    APPROVAL_ID_RE.test(id)
  );
}

export function isValidClientIdShape(id: string): boolean {
  return (
    typeof id === "string" &&
    id.length > 0 &&
    id.length <= MAX_CLIENT_ID_CHARS &&
    CLIENT_ID_RE.test(id)
  );
}

// 16 bytes of CSPRNG output, base64url (22 chars). Kept from gvnr (decision D3): the id is only
// ever transported inside an HMAC-signed token, so it needs uniqueness, not capability strength.
export function generateApprovalId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// The structured half of decision D6: what the agent is actually about to do, hashed into the
// chain so the human can never be shown one thing while another is witnessed.
export interface ActionPayload {
  tool: string;
  args?: unknown;
}

export interface ApprovalRecord {
  id: string;
  agentId: string;
  // Ties the approval's chain events (approval.requested / approval.decided) to the same
  // session as the rest of the agent's evidence — required for the audit-day story.
  sessionId: string;
  actionSummary: string;
  actionPayload: ActionPayload | null;
  actionPayloadHash: string | null;
  status: ApprovalStatus;
  responderId: string | null;
  reason: string | null;
  channels: string[];
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  callbackUrl: string | null;
}

export interface ApprovalCreateResult {
  approvalId: string;
  expiresAt: string;
  record: ApprovalRecord;
}

export type DecideFailureReason = "not_found" | "already_decided" | "expired";

export interface DecideResult {
  ok: boolean;
  reason?: DecideFailureReason;
  record?: ApprovalRecord;
}

// Timeout is computed on read, never stored (decision D3 keeps gvnr's pattern):
// the stored status stays 'pending' and flips to 'timeout' in the response the
// moment expires_at passes. No DO alarms involved.
export function statusOnRead(
  stored: ApprovalStatus,
  expiresAt: string,
  now: number,
): ApprovalStatus {
  if (stored === "pending" && now > Date.parse(expiresAt)) return "timeout";
  return stored;
}

// What the go.kajaril.com worker is allowed to ask of audit-event-mcp over the
// service binding (named entrypoint ApprovalInternal in src/main.ts). Nothing here
// creates approvals — creation only happens through the authenticated MCP/REST surface.
export interface ApprovalInternalClient {
  getApproval(clientId: string, approvalId: string): Promise<ApprovalRecord | null>;
  decideApproval(params: {
    clientId: string;
    approvalId: string;
    decision: ApprovalDecision;
    reason?: string;
    responderId?: string;
  }): Promise<DecideResult>;
}
