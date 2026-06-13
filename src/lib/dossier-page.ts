import type { DossierRow } from "@/lib/dossier";

// Human-readable dossier (Day 5): the evidence-consumer surface — "two interactions for a
// lawyer" (draft §2): read this page, then drag the raw file onto /verify. Same security
// posture as the approve page: zero JS, every exported field escaped (purposes and agent
// ids are tenant-authored, i.e. attacker-influenced from this worker's point of view).

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function shortHash(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 8)}…${hash.slice(-8)}` : hash;
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#e5e5e5;padding:32px 18px;min-height:100vh}
.wrap{max-width:980px;margin:0 auto}
h1{font-size:1.3rem;font-weight:600;letter-spacing:-0.01em;margin-bottom:6px}
.sub{font-size:0.85rem;color:#888;margin-bottom:18px}
.sub strong{color:#e5e5e5}
.mono{font-family:"SF Mono","Fira Code",monospace}
.actions{margin:0 0 22px;display:flex;gap:10px;flex-wrap:wrap}
.actions a{display:inline-block;padding:10px 16px;border-radius:9px;font-size:0.85rem;font-weight:600;text-decoration:none;border:1px solid #2a2a2a;color:#e5e5e5;background:#1a1a1a}
.actions a.primary{background:#16a34a;border-color:#16a34a;color:#fff}
table{width:100%;border-collapse:collapse;font-size:0.8rem}
th{text-align:left;color:#888;font-weight:600;padding:8px 10px;border-bottom:1px solid #2a2a2a;white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid #1a1a1a;color:#ccc;vertical-align:top}
td.mono{font-size:0.72rem;color:#8b8b8b;word-break:break-all}
.type{font-family:"SF Mono","Fira Code",monospace;color:#a78bfa;white-space:nowrap}
.tick{color:#86efac}
.dash{color:#555}
.note{font-size:0.78rem;color:#777;margin-top:16px;line-height:1.6}
.state{padding:18px 16px;border-radius:9px;font-size:0.9rem;text-align:center;font-weight:500;max-width:420px;margin:40px auto}
.state-notfound{background:#1a1a1a;color:#a8a8a8;border:1px solid #2a2a2a}
.foot{font-size:0.72rem;color:#555;margin-top:26px;text-align:center}
.foot a{color:#777;text-decoration:none}
</style>
</head>
<body><div class="wrap">${body}</div></body></html>`;
}

const FOOT = `<div class="foot">— <a href="https://kajaril.com">kajaril</a> · the neutral witness for agent actions</div>`;

export function renderDossierPage(params: {
  rows: DossierRow[];
  clientId: string;
  token: string;
  subjectId: string | null;
  expiresAt: string | null;
}): string {
  const { rows } = params;
  const subject = params.subjectId ?? rows.find((r) => r.subject_id)?.subject_id ?? "—";
  const notarized = rows.filter((r) => r.merkle_root && r.notary_sig).length;
  const rawHref = `/dossier/${encodeURIComponent(params.clientId)}/${encodeURIComponent(params.token)}/raw`;

  const tableRows = rows
    .map(
      (r) => `<tr>
  <td style="white-space:nowrap">${escapeHtml(r.created_at)}</td>
  <td class="type">${escapeHtml(r.event_type)}</td>
  <td>${escapeHtml(r.agent_id)}</td>
  <td>${escapeHtml(r.purpose)}</td>
  <td>${escapeHtml(r.lawful_basis ?? "—")}</td>
  <td class="mono" title="chain hash">${escapeHtml(shortHash(r.chain_hash))}</td>
  <td>${r.merkle_root && r.notary_sig ? '<span class="tick">✓</span>' : '<span class="dash">—</span>'}</td>
</tr>`,
    )
    .join("\n");

  return pageShell(
    "Audit dossier",
    `
<h1>Audit dossier</h1>
<div class="sub">
  Subject <strong class="mono">${escapeHtml(subject)}</strong>
  · ${rows.length} event${rows.length === 1 ? "" : "s"}
  · ${notarized} notarized
  ${params.expiresAt ? ` · download link expires ${escapeHtml(params.expiresAt)}` : ""}
</div>
<div class="actions">
  <a class="primary" href="/verify">Verify this dossier</a>
  <a href="${rawHref}" download>Download evidence file (JSONL)</a>
</div>
<table>
<thead><tr><th>Time (UTC)</th><th>Event</th><th>Agent</th><th>Purpose</th><th>Lawful basis</th><th>Fingerprint</th><th>Notary</th></tr></thead>
<tbody>
${tableRows}
</tbody>
</table>
<div class="note">
  Every event carries a tamper-evident fingerprint that commits to all events before it.
  Notarized events (✓) are additionally covered by an Ed25519 signature from the kajaril
  notary; events without one are awaiting the next notarization batch (≤ 15 minutes).
  To check independently: download the evidence file, open <span class="mono">/verify</span>,
  and drop the file there — verification runs entirely in your browser against the
  published notary key.
</div>
${FOOT}`,
  );
}

export function renderDossierStatePage(title: string, message: string): string {
  return pageShell(
    title,
    `
<div class="state state-notfound"><strong>${escapeHtml(title)}</strong><br>${escapeHtml(message)}</div>
${FOOT}`,
  );
}
