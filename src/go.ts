import { Hono } from "hono";
import type { ApprovalRecord } from "@/lib/approval";
import { MAX_REASON_CHARS } from "@/lib/approval";
import { verifyApprovalToken } from "@/lib/token";
import type { GoEnv } from "@/lib/types";

// go.kajaril.com — the only public human surface (decision D1). Hosts the approve page;
// /verify and dossier downloads join it on Day 5. Approve pages ported from gvnr
// src/routes/approve.ts (donor, read-only): no inline JS anywhere — buttons submit plain
// HTML forms; decisions are state-changing POSTs so link scanners that prefetch GET
// can never decide anything.

const app = new Hono<{ Bindings: GoEnv }>();

const PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'";

function securityHeaders(c: { header: (name: string, value: string) => void }): void {
  c.header("Content-Security-Policy", PAGE_CSP);
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Cache-Control", "no-store");
  // The approval URL is a bearer credential — never leak it via Referer to any link the page renders.
  c.header("Referrer-Policy", "no-referrer");
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pageShell(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)} — kajaril</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#e5e5e5;padding:32px 18px;min-height:100vh;display:flex;align-items:flex-start;justify-content:center}
.card{background:#111;border:1px solid #1f1f1f;border-radius:14px;padding:24px;max-width:420px;width:100%}
h1{font-size:1.2rem;font-weight:600;letter-spacing:-0.01em;margin-bottom:14px}
.row{font-size:0.85rem;color:#888;margin-bottom:6px}
.row strong{color:#e5e5e5;font-weight:600}
.agent{font-family:"SF Mono","Fira Code",monospace;color:#a78bfa}
.hash{font-family:"SF Mono","Fira Code",monospace;font-size:0.72rem;color:#666;word-break:break-all}
.action{background:#0f0f0f;border:1px solid #1f1f1f;border-radius:8px;padding:12px 14px;font-size:0.92rem;color:#ccc;margin:8px 0 18px;line-height:1.5}
.expires{font-size:0.8rem;color:#888;margin-bottom:20px}
form{display:block;margin:0}
form + form{margin-top:10px}
button{width:100%;padding:13px 16px;border:none;border-radius:9px;font-size:0.95rem;font-weight:600;cursor:pointer;font-family:inherit;transition:opacity 0.15s}
button:hover{opacity:0.88}
.approve{background:#16a34a;color:#fff}
.deny{background:#1a1a1a;color:#e5e5e5;border:1px solid #2a2a2a}
textarea{width:100%;background:#0f0f0f;border:1px solid #2a2a2a;border-radius:8px;color:#e5e5e5;font-family:inherit;font-size:0.85rem;padding:10px 12px;margin-bottom:10px;resize:vertical;min-height:54px}
textarea::placeholder{color:#555}
.state{padding:18px 16px;border-radius:9px;font-size:0.9rem;text-align:center;font-weight:500}
.state-approved{background:#0a2a14;color:#86efac;border:1px solid #14532d}
.state-denied{background:#2a0a0a;color:#fca5a5;border:1px solid #532d2d}
.state-timeout{background:#2a1a0a;color:#fcd34d;border:1px solid #533a14}
.state-notfound{background:#1a1a1a;color:#a8a8a8;border:1px solid #2a2a2a}
.reason{font-size:0.82rem;color:#999;margin-top:12px;text-align:center;line-height:1.5}
.foot{font-size:0.72rem;color:#555;margin-top:22px;text-align:center}
.foot a{color:#777;text-decoration:none}
</style>
</head>
<body>${body}</body></html>`;
}

const FOOT = `<div class="foot">— <a href="https://kajaril.com">kajaril</a> · the neutral witness for agent actions</div>`;

function renderPending(record: ApprovalRecord, token: string): string {
  const expiresMin = Math.max(1, Math.round((Date.parse(record.expiresAt) - Date.now()) / 60_000));
  const hashRow = record.actionPayloadHash
    ? `<div class="row"><strong>Action hash</strong></div><div class="hash">${escapeHtml(record.actionPayloadHash)}</div>`
    : "";
  const action = `/a/${encodeURIComponent(token)}/decide`;
  return pageShell(
    "Approve action?",
    `
<div class="card">
  <h1>Approve agent action?</h1>
  <div class="row"><strong>Agent</strong> · <span class="agent">${escapeHtml(record.agentId)}</span></div>
  <div class="action">${escapeHtml(record.actionSummary)}</div>
  ${hashRow}
  <div class="expires">Expires in ~${expiresMin} min</div>
  <form method="POST" action="${action}">
    <input type="hidden" name="decision" value="approved">
    <button type="submit" class="approve">Approve</button>
  </form>
  <form method="POST" action="${action}">
    <input type="hidden" name="decision" value="denied">
    <textarea name="reason" maxlength="${MAX_REASON_CHARS}" placeholder="Reason (optional — recorded with the denial)"></textarea>
    <button type="submit" class="deny">Deny</button>
  </form>
  ${FOOT}
</div>`,
  );
}

function renderTerminal(record: ApprovalRecord): string {
  const label =
    record.status === "approved"
      ? "Approved"
      : record.status === "denied"
        ? "Denied"
        : record.status === "timeout"
          ? "Expired before decision"
          : "Pending";
  const cls =
    record.status === "approved"
      ? "state-approved"
      : record.status === "denied"
        ? "state-denied"
        : "state-timeout";
  const reasonRow = record.reason
    ? `<div class="reason">Reason: ${escapeHtml(record.reason)}</div>`
    : "";

  return pageShell(
    label,
    `
<div class="card">
  <h1>${label}</h1>
  <div class="row"><strong>Agent</strong> · <span class="agent">${escapeHtml(record.agentId)}</span></div>
  <div class="action">${escapeHtml(record.actionSummary)}</div>
  <div class="state ${cls}">${label}${record.decidedAt ? ` · ${new Date(record.decidedAt).toUTCString()}` : ""}</div>
  ${reasonRow}
  ${FOOT}
</div>`,
  );
}

function renderNotFound(): string {
  return pageShell(
    "Not found",
    `
<div class="card">
  <h1>Approval not found</h1>
  <div class="state state-notfound">This approval link is invalid or has expired.</div>
  ${FOOT}
</div>`,
  );
}

// Fail closed, mirroring index.ts: without the token secret we cannot verify any link,
// and an unverified link must never reach a tenant.
function misconfigured(): Response {
  return Response.json(
    {
      error: "Server misconfigured",
      detail: "APPROVAL_TOKEN_SECRET is not set; refusing to process approval links",
    },
    { status: 503 },
  );
}

app.get("/health", (c) => {
  return c.json({ status: "ok", product: "go-kajaril", version: "0.1.0" });
});

app.get("/a/:token", async (c) => {
  securityHeaders(c);
  if (!c.env.APPROVAL_TOKEN_SECRET) return misconfigured();

  const payload = await verifyApprovalToken(c.env.APPROVAL_TOKEN_SECRET, c.req.param("token"));
  if (!payload) return c.html(renderNotFound(), 404);

  const record = await c.env.AUDIT.getApproval(payload.clientId, payload.approvalId);
  if (!record) return c.html(renderNotFound(), 404);
  if (record.status === "pending") return c.html(renderPending(record, c.req.param("token")));
  return c.html(renderTerminal(record));
});

app.post("/a/:token/decide", async (c) => {
  securityHeaders(c);
  if (!c.env.APPROVAL_TOKEN_SECRET) return misconfigured();

  const payload = await verifyApprovalToken(c.env.APPROVAL_TOKEN_SECRET, c.req.param("token"));
  if (!payload) return c.html(renderNotFound(), 404);

  let decision: string | undefined;
  let reason: string | undefined;
  const contentType = c.req.header("Content-Type") ?? "";
  if (
    contentType.includes("application/x-www-form-urlencoded") ||
    contentType.includes("multipart/form-data")
  ) {
    const form = await c.req.formData();
    const rawDecision = form.get("decision");
    decision = typeof rawDecision === "string" ? rawDecision : undefined;
    const rawReason = form.get("reason");
    reason =
      typeof rawReason === "string" ? rawReason.trim().slice(0, MAX_REASON_CHARS) : undefined;
    if (reason === "") reason = undefined;
  }

  if (decision !== "approved" && decision !== "denied") {
    return c.html(
      pageShell(
        "Invalid request",
        `
<div class="card">
  <h1>Invalid decision</h1>
  <div class="state state-notfound">Expected "approved" or "denied".</div>
  ${FOOT}
</div>`,
      ),
      400,
    );
  }

  // Best-effort attribution only — 48-bit truncated SHA-256 of the caller IP, not a security
  // identifier. Magic-link identity (D8) replaces this as responder_id on Day 3.
  const ip = c.req.header("CF-Connecting-IP");
  const responderId = ip ? `ip:${await hashShort(ip)}` : "anonymous";

  const result = await c.env.AUDIT.decideApproval({
    clientId: payload.clientId,
    approvalId: payload.approvalId,
    decision,
    reason,
    responderId,
  });

  if (!result.ok) {
    if (result.record) return c.html(renderTerminal(result.record));
    return c.html(renderNotFound(), 404);
  }
  if (!result.record) return c.html(renderNotFound(), 404);
  return c.html(renderTerminal(result.record));
});

async function hashShort(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  const arr = Array.from(new Uint8Array(buf)).slice(0, 6);
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default { fetch: app.fetch };
