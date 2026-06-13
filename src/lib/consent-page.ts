import type { ClientInfo } from "@cloudflare/workers-oauth-provider";
import type { M2MScope } from "@/lib/m2m";

// OAuth consent screen (D11). Same no-JS posture as the go worker's approve page: plain
// HTML forms, every attacker-influenced field escaped, CSP forbids script entirely. DCR
// means client metadata is hostile by default (D11 condition 5) — client_name is an
// arbitrary registrant-supplied string, so it is rendered as text, never markup, and the
// registrant's URI fields (logo/client/policy/tos) are deliberately not rendered at all
// in v1: a lookalike logo or link on a consent screen is a phishing tool, not a feature.

export const CONSENT_PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; form-action 'self'; frame-ancestors 'none'";

export function consentSecurityHeaders(c: { header: (name: string, value: string) => void }): void {
  c.header("Content-Security-Policy", CONSENT_PAGE_CSP);
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Cache-Control", "no-store");
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
.card{background:#111;border:1px solid #1f1f1f;border-radius:14px;padding:24px;max-width:440px;width:100%}
h1{font-size:1.2rem;font-weight:600;letter-spacing:-0.01em;margin-bottom:14px}
.row{font-size:0.85rem;color:#888;margin-bottom:6px}
.row strong{color:#e5e5e5;font-weight:600}
.mono{font-family:"SF Mono","Fira Code",monospace;color:#a78bfa;word-break:break-all}
.client{background:#0f0f0f;border:1px solid #1f1f1f;border-radius:8px;padding:12px 14px;font-size:0.92rem;color:#ccc;margin:8px 0 14px;line-height:1.5;word-break:break-word}
.scopes{margin:0 0 18px;padding:0;list-style:none}
.scopes li{background:#0f0f0f;border:1px solid #1f1f1f;border-radius:8px;padding:10px 14px;font-size:0.85rem;color:#ccc;margin-bottom:8px;line-height:1.5}
.scopes .name{font-family:"SF Mono","Fira Code",monospace;color:#a78bfa}
form{display:block;margin:0}
form + form{margin-top:10px}
button{width:100%;padding:13px 16px;border:none;border-radius:9px;font-size:0.95rem;font-weight:600;cursor:pointer;font-family:inherit;transition:opacity 0.15s}
button:hover{opacity:0.88}
.approve{background:#16a34a;color:#fff}
.deny{background:#1a1a1a;color:#e5e5e5;border:1px solid #2a2a2a}
.state{padding:18px 16px;border-radius:9px;font-size:0.9rem;text-align:center;font-weight:500}
.state-error{background:#2a0a0a;color:#fca5a5;border:1px solid #532d2d}
.foot{font-size:0.72rem;color:#555;margin-top:22px;text-align:center}
.foot a{color:#777;text-decoration:none}
</style>
</head>
<body>${body}</body></html>`;
}

const FOOT = `<div class="foot">— <a href="https://kajaril.com">kajaril</a> · the neutral witness for agent actions</div>`;

const SCOPE_DESCRIPTIONS: Record<M2MScope, string> = {
  agent:
    "record audit events, request approvals, and poll decisions — cannot read chains or export dossiers",
  admin:
    "full access: everything above plus chain verification, event queries, dossier export, and credential rotation",
};

// Where the user will be sent after deciding. Shown so a human can spot a redirect they do
// not recognize; rendered as escaped text, never a link.
function describeRedirect(redirectUri: string): string {
  try {
    const url = new URL(redirectUri);
    if (url.protocol === "http:" || url.protocol === "https:") return url.origin;
    return `${url.protocol}//…`;
  } catch {
    return "(unparseable redirect)";
  }
}

export function renderConsentPage(params: {
  client: ClientInfo;
  tenant: string;
  scopes: readonly M2MScope[];
  redirectUri: string;
  stateBlob: string;
}): string {
  const clientName = params.client.clientName?.trim() || "(unnamed client)";
  const scopeItems = params.scopes
    .map(
      (s) =>
        `<li><span class="name">${escapeHtml(s)}</span> — ${escapeHtml(SCOPE_DESCRIPTIONS[s])}</li>`,
    )
    .join("");
  const form = (decision: "approve" | "deny", cls: string, label: string) => `
  <form method="POST" action="/oauth/authorize/decision">
    <input type="hidden" name="consent_state" value="${escapeHtml(params.stateBlob)}">
    <input type="hidden" name="decision" value="${decision}">
    <button type="submit" class="${cls}">${label}</button>
  </form>`;

  return pageShell(
    "Authorize access?",
    `
<div class="card">
  <h1>Authorize this application?</h1>
  <div class="client">${escapeHtml(clientName)}</div>
  <div class="row"><strong>Client ID</strong> · <span class="mono">${escapeHtml(params.client.clientId)}</span></div>
  <div class="row"><strong>Tenant</strong> · <span class="mono">${escapeHtml(params.tenant)}</span></div>
  <div class="row" style="margin-bottom:12px"><strong>Returns to</strong> · <span class="mono">${escapeHtml(describeRedirect(params.redirectUri))}</span></div>
  <ul class="scopes">${scopeItems}</ul>
  ${form("approve", "approve", "Authorize")}
  ${form("deny", "deny", "Deny")}
  ${FOOT}
</div>`,
  );
}

export function renderConsentErrorPage(title: string, message: string): string {
  return pageShell(
    title,
    `
<div class="card">
  <h1>${escapeHtml(title)}</h1>
  <div class="state state-error">${escapeHtml(message)}</div>
  ${FOOT}
</div>`,
  );
}
