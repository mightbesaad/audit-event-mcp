import type { ApprovalRecord } from "@/lib/approval";

// Email fallback channel (D4), ported from gvnr src/lib/notify.ts (donor, read-only).
// Email is the slow rung of the channel ladder: it is never sent inline with
// request_approval — the DO's escalation alarm fires it, either immediately (no instant
// channel reached the approver) or after the 10-minute unacked window (lib/approval.ts).

const RESEND_ENDPOINT = "https://api.resend.com/emails";
// send.kajaril.com is the Resend-verified sending domain (EU region). NEVER the root
// domain: kajaril.com has no SPF/DKIM delegation to Resend, and approval mail must not
// ride on the root domain's sending reputation. Replies go to a human instead.
export const EMAIL_FROM = "kajaril approvals <approvals@send.kajaril.com>";
export const EMAIL_REPLY_TO = "studio@kajaril.com";
const SEND_TIMEOUT_MS = 10_000;

// Approver email config lives next to the telegram bindings in CHANNELS_KV (routing
// state, never evidence) — set via the admin-scoped POST /channels/email.
export function kvEmailForClient(clientId: string): string {
  return `email:${clientId}`;
}

export const MAX_EMAIL_ADDRESS_CHARS = 254;
const EMAIL_SHAPE_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmailShape(address: string): boolean {
  return (
    typeof address === "string" &&
    address.length <= MAX_EMAIL_ADDRESS_CHARS &&
    EMAIL_SHAPE_RE.test(address)
  );
}

export type EmailDispatchStatus = "sent" | "failed" | "skipped_no_key";

export interface EmailDispatchResult {
  status: EmailDispatchStatus;
  error?: string;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function buildApprovalEmail(
  record: ApprovalRecord,
  approvalUrl: string,
  nowMs: number = Date.now(),
): { subject: string; text: string; html: string } {
  const expiresMin = Math.max(1, Math.round((Date.parse(record.expiresAt) - nowMs) / 60_000));
  const subject = `Approval requested: ${record.agentId}`;
  const tool = record.actionPayload?.tool;

  const text = [
    `Agent "${record.agentId}" is requesting your approval.`,
    "",
    `Action: ${record.actionSummary}`,
    ...(tool ? [`Tool: ${tool}`] : []),
    ...(record.actionPayloadHash ? [`Action hash: ${record.actionPayloadHash}`] : []),
    `Expires in: ~${expiresMin} minutes`,
    "",
    `Approve or deny: ${approvalUrl}`,
    "",
    "— kajaril · the neutral witness for agent actions · https://kajaril.com",
  ].join("\n");

  const toolRow = tool
    ? `<p style="font-size:0.85rem;color:#888;margin:0 0 6px">Tool · <code style="color:#a78bfa;font-family:monospace">${escapeHtml(tool)}</code></p>`
    : "";
  const hashRow = record.actionPayloadHash
    ? `<p style="font-size:0.7rem;color:#666;font-family:monospace;word-break:break-all;margin:0 0 14px">${escapeHtml(record.actionPayloadHash)}</p>`
    : "";

  const html = `<!DOCTYPE html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e5e5e5;padding:32px 16px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#111;border:1px solid #1f1f1f;border-radius:12px;padding:24px">
    <h1 style="font-size:1.1rem;font-weight:600;margin:0 0 14px;color:#e5e5e5">Approval requested</h1>
    <p style="font-size:0.92rem;color:#bbb;margin:0 0 8px">Agent <code style="color:#a78bfa;font-family:monospace">${escapeHtml(record.agentId)}</code> is requesting your approval.</p>
    <p style="font-size:0.92rem;color:#bbb;margin:14px 0 6px"><strong style="color:#e5e5e5">Action</strong></p>
    <p style="font-size:0.92rem;color:#ccc;background:#0f0f0f;border:1px solid #1f1f1f;border-radius:6px;padding:10px 12px;margin:0 0 14px">${escapeHtml(record.actionSummary)}</p>
    ${toolRow}
    ${hashRow}
    <p style="font-size:0.82rem;color:#888;margin:0 0 20px">Expires in ~${expiresMin} minutes.</p>
    <p style="margin:0 0 20px"><a href="${approvalUrl}" style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;padding:11px 22px;border-radius:8px;font-weight:500;font-size:0.95rem">Open approval page</a></p>
    <p style="font-size:0.74rem;color:#666;margin:0">If the button does not work, copy this link: <span style="color:#888;word-break:break-all">${approvalUrl}</span></p>
  </div>
  <p style="text-align:center;font-size:0.72rem;color:#555;margin:24px 0 0">— kajaril · <a href="https://kajaril.com" style="color:#666">the neutral witness for agent actions</a></p>
</body></html>`;

  return { subject, text, html };
}

// Single attempt, never throws — the DO alarm records the result on the escalation row;
// a retrying outbox is v1.5 (DEFERRED.md). The approvalUrl is interpolated into href/text
// unescaped on purpose: it is minted by us (mintApprovalUrl), never caller-supplied.
export async function sendApprovalEmail(
  apiKey: string | undefined,
  to: string,
  record: ApprovalRecord,
  approvalUrl: string,
): Promise<EmailDispatchResult> {
  if (!apiKey) return { status: "skipped_no_key" };

  const { subject, text, html } = buildApprovalEmail(record, approvalUrl);
  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [to],
        reply_to: EMAIL_REPLY_TO,
        subject,
        text,
        html,
      }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return { status: "failed", error: `resend_${res.status}: ${body.slice(0, 200)}` };
    }
    return { status: "sent" };
  } catch (err) {
    return { status: "failed", error: err instanceof Error ? err.message : "unknown_error" };
  }
}
