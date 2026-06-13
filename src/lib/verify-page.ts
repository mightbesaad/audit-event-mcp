// Public /verify page (Day 5, draft §2 evidence-consumer trail): drag a dossier on, get
// green ticks and a plain-language verdict. Verification is CLIENT-SIDE on purpose — the
// neutrality claim only holds if the auditor's own browser recomputes the fingerprints and
// checks the notary signatures against the published key; a server that grades its own
// homework proves nothing. The page therefore needs JS: CSP allows scripts from 'self'
// only (the one file below), inline script stays forbidden, and the script builds DOM via
// textContent exclusively — dossier content never meets innerHTML.

export const VERIFY_PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'none'; form-action 'none'; frame-ancestors 'none'";

// Served at /verify.js. Plain browser JS (no TS syntax — shipped verbatim). The pure core
// (kajarilVerifyDossier) is DOM-free and exercised by test/verify.test.ts via this exact
// string, so what the tests prove is what auditors run. Verification message for each
// notary signature is the raw 32 merkle-root bytes (hex-decoded) — exactly what
// src/notary.ts signs.
export const VERIFY_SCRIPT = `"use strict";

function kjrHexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) return null;
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function kjrSha256Hex(subtle, text) {
  var digest = await subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map(function (b) { return b.toString(16).padStart(2, "0"); })
    .join("");
}

// Folds a Merkle inclusion proof from a leaf up to a root, mirroring buildMerkleProofs:
// sibling on the left → SHA-256(sibling + node), on the right → SHA-256(node + sibling).
// Returns the computed root hex, or null if the proof is missing/malformed.
async function kjrFoldProof(subtle, leafHash, proof) {
  if (!Array.isArray(proof)) return null;
  var node = leafHash;
  for (var i = 0; i < proof.length; i++) {
    var step = proof[i];
    if (!step || typeof step.hash !== "string" || /[^0-9a-f]/.test(step.hash) ||
        step.hash.length !== 64) {
      return null;
    }
    node = step.left
      ? await kjrSha256Hex(subtle, step.hash + node)
      : await kjrSha256Hex(subtle, node + step.hash);
  }
  return node;
}

// Pure verifier. Returns a report object; never throws on hostile input.
// Checks, in order:
//   1. parse        — the file is well-formed JSONL with the dossier fields
//   2. fingerprints — each record's chain_hash recomputes from its preimage
//                     (id | event_type | input_hash ?? omitted_reason | prev_hash)
//   3. notary       — for every record that claims notarization (carries merkle_root +
//                     notary_sig), BOTH must hold: its merkle_proof folds to that root
//                     (the record was really in the signed batch), AND the root's
//                     Ed25519 signature verifies against the published notary key. A
//                     borrowed-but-genuine signature stapled onto fabricated records
//                     fails the inclusion half — the record is not in the tree it claims.
async function kajarilVerifyDossier(text, pubkeyHex, subtle) {
  var report = {
    parse: { ok: false, count: 0 },
    fingerprints: { checked: 0, passed: 0, failed: [], uncheckable: 0 },
    linkage: { linked: 0 },
    notary: {
      claimedRecords: 0,
      attestedRecords: 0,
      roots: 0,
      verifiedRoots: 0,
      failedRoots: [],
      brokenInclusion: [],
      keyUsable: true,
    },
    verdict: "invalid",
  };

  var rows = [];
  var lines = String(text).split(/\\r?\\n/);
  for (var li = 0; li < lines.length; li++) {
    var line = lines[li];
    if (!line.trim()) continue;
    var row;
    try { row = JSON.parse(line); } catch (e) { return report; }
    if (!row || typeof row !== "object" || typeof row.id !== "string" ||
        typeof row.event_type !== "string" || typeof row.chain_hash !== "string") {
      return report;
    }
    rows.push(row);
  }
  if (rows.length === 0) return report;
  report.parse.ok = true;
  report.parse.count = rows.length;

  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var slot = typeof r.input_hash === "string" ? r.input_hash
      : typeof r.input_hash_omitted_reason === "string" ? r.input_hash_omitted_reason
      : null;
    if (slot === null) { report.fingerprints.uncheckable++; continue; }
    var prev = typeof r.prev_hash === "string" ? r.prev_hash : "";
    var expected = await kjrSha256Hex(subtle, r.id + "|" + r.event_type + "|" + slot + "|" + prev);
    report.fingerprints.checked++;
    if (expected === r.chain_hash) {
      report.fingerprints.passed++;
    } else {
      report.fingerprints.failed.push(r.id);
    }
    if (i > 0 && r.prev_hash === rows[i - 1].chain_hash) report.linkage.linked++;
  }

  // A record "claims notarization" only if it carries BOTH merkle_root and notary_sig.
  // Collect the distinct (root → sig) it claims; a lone field is ignored (treated as not
  // notarized) rather than trusted.
  var rootSigs = new Map();
  var claimed = [];
  for (var j = 0; j < rows.length; j++) {
    var row2 = rows[j];
    if (typeof row2.merkle_root === "string" && typeof row2.notary_sig === "string") {
      report.notary.claimedRecords++;
      claimed.push(row2);
      if (!rootSigs.has(row2.merkle_root)) rootSigs.set(row2.merkle_root, row2.notary_sig);
    }
  }
  report.notary.roots = rootSigs.size;

  if (rootSigs.size > 0) {
    // Step A — verify each distinct root's Ed25519 signature (needs the published key).
    var rootValid = new Map();
    var pubBytes = kjrHexToBytes(pubkeyHex || "");
    var key = null;
    if (pubBytes && pubBytes.length === 32) {
      try {
        key = await subtle.importKey("raw", pubBytes, { name: "Ed25519" }, false, ["verify"]);
      } catch (e) {
        key = null;
      }
    }
    if (!key) {
      report.notary.keyUsable = false;
    } else {
      var entries = Array.from(rootSigs.entries());
      for (var k = 0; k < entries.length; k++) {
        var root = entries[k][0];
        var rootBytes = kjrHexToBytes(root);
        var sigBytes = kjrHexToBytes(entries[k][1]);
        var ok = false;
        if (rootBytes && sigBytes) {
          try {
            ok = await subtle.verify({ name: "Ed25519" }, key, sigBytes, rootBytes);
          } catch (e) {
            ok = false;
          }
        }
        rootValid.set(root, ok);
        if (ok) report.notary.verifiedRoots++;
        else report.notary.failedRoots.push(root);
      }
    }

    // Step B — for each claiming record, fold its inclusion proof to its claimed root. This
    // is what stops a borrowed genuine signature from validating fabricated records: the
    // fold needs the record's leaf to actually sit under the signed root. Independent of the
    // key, so it still runs (and can still fail "broken") when the key is unusable.
    for (var m = 0; m < claimed.length; m++) {
      var cr = claimed[m];
      var leaf = await kjrSha256Hex(subtle, cr.id + "|" + cr.chain_hash);
      var folded = await kjrFoldProof(subtle, leaf, cr.merkle_proof);
      var inclusionOk = folded !== null && folded === cr.merkle_root;
      if (!inclusionOk) {
        report.notary.brokenInclusion.push(cr.id);
        continue;
      }
      if (report.notary.keyUsable && rootValid.get(cr.merkle_root) === true) {
        report.notary.attestedRecords++;
      }
    }
  }

  var tampered =
    report.fingerprints.failed.length > 0 ||
    report.notary.failedRoots.length > 0 ||
    report.notary.brokenInclusion.length > 0;
  var allFingerprintsPass =
    report.fingerprints.uncheckable === 0 &&
    report.fingerprints.passed === report.parse.count;
  if (tampered) {
    report.verdict = "failed";
  } else if (report.notary.claimedRecords > 0 && !report.notary.keyUsable) {
    report.verdict = "unverifiable";
  } else if (allFingerprintsPass && report.notary.attestedRecords > 0) {
    report.verdict = "verified";
  } else if (allFingerprintsPass) {
    report.verdict = "unattested";
  } else {
    report.verdict = "partial";
  }
  return report;
}

// --- DOM glue (skipped under test, where only the core runs) ---
if (typeof document !== "undefined") {
  (function () {
    var drop = document.getElementById("drop");
    var input = document.getElementById("file");
    var results = document.getElementById("results");
    var verdictEl = document.getElementById("verdict");

    function addTick(ok, text) {
      var li = document.createElement("li");
      li.className = ok === true ? "pass" : ok === false ? "fail" : "warn";
      li.textContent = (ok === true ? "✓ " : ok === false ? "✗ " : "△ ") + text;
      results.appendChild(li);
    }

    function setVerdict(cls, text) {
      verdictEl.className = "verdict " + cls;
      verdictEl.textContent = text;
    }

    async function run(file) {
      results.textContent = "";
      setVerdict("checking", "Checking " + file.name + " …");
      var text = await file.text();

      var pubkeyHex = "";
      try {
        var res = await fetch("/.well-known/notary-pubkey");
        if (res.ok) pubkeyHex = (await res.json()).publicKey || "";
      } catch (e) { /* handled below as unverifiable */ }

      var r = await kajarilVerifyDossier(text, pubkeyHex, crypto.subtle);

      if (!r.parse.ok) {
        addTick(false, "This file is not a kajaril dossier (expected one JSON record per line).");
        setVerdict("fail", "Cannot verify: the file does not parse as a dossier.");
        return;
      }
      addTick(true, "Well-formed dossier — " + r.parse.count + " record" + (r.parse.count === 1 ? "" : "s") + ".");

      if (r.fingerprints.failed.length > 0) {
        addTick(false, "Tamper-evident fingerprint check FAILED for " + r.fingerprints.failed.length +
          " record(s): " + r.fingerprints.failed.join(", "));
      } else if (r.fingerprints.uncheckable > 0) {
        addTick(null, "Fingerprints recomputed for " + r.fingerprints.passed + " of " + r.parse.count +
          " records (" + r.fingerprints.uncheckable + " exported without preimage fields).");
      } else {
        addTick(true, "Every record's tamper-evident fingerprint recomputes correctly (" +
          r.fingerprints.passed + " of " + r.parse.count + ").");
      }

      if (r.notary.brokenInclusion.length > 0) {
        addTick(false, "Notary inclusion check FAILED for " + r.notary.brokenInclusion.length +
          " record(s): they carry a notary signature but are NOT inside the batch it signed — " +
          "the hallmark of a genuine signature stapled onto records that were never witnessed.");
      }
      if (r.notary.claimedRecords === 0) {
        addTick(null, "No notary signatures present yet — records are notarized in batches (≤ 15 min).");
      } else if (!r.notary.keyUsable) {
        addTick(null, "Could not check notary signatures: the notary key was unavailable or this browser lacks Ed25519 support (use a current Chrome, Firefox, or Safari).");
      } else if (r.notary.failedRoots.length > 0) {
        addTick(false, "Notary signature verification FAILED for " + r.notary.failedRoots.length + " batch root(s).");
      } else if (r.notary.brokenInclusion.length === 0) {
        addTick(true, "Every notarized record proves it was inside a batch signed by the kajaril " +
          "notary, and all signatures verify against the published key (" +
          r.notary.attestedRecords + " of " + r.parse.count + " records attested across " +
          r.notary.roots + " batch" + (r.notary.roots === 1 ? "" : "es") + ").");
      }

      if (r.verdict === "verified") {
        setVerdict("pass", "Verified: every notarized record proves it was inside a batch the kajaril " +
          "notary signed, and the record's chain fingerprint is intact. (Coverage is the event id, " +
          "type, and input/previous digests — the fields committed to the chain.)");
      } else if (r.verdict === "unattested") {
        setVerdict("warn", "Internally consistent, but not yet notarized — every fingerprint checks out; notary signatures will cover these records after the next batch.");
      } else if (r.verdict === "unverifiable") {
        setVerdict("warn", "Could not complete verification in this browser. The dossier was NOT shown to be invalid.");
      } else if (r.verdict === "partial") {
        setVerdict("warn", "Partially verified: every checkable record passed, but some records could not be recomputed.");
      } else {
        setVerdict("fail", "VERIFICATION FAILED: this dossier does not match what was witnessed. Do not rely on it.");
      }
    }

    input.addEventListener("change", function () {
      if (input.files && input.files[0]) run(input.files[0]);
    });
    drop.addEventListener("dragover", function (e) { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", function () { drop.classList.remove("over"); });
    drop.addEventListener("drop", function (e) {
      e.preventDefault();
      drop.classList.remove("over");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) run(e.dataTransfer.files[0]);
    });
  })();
}
`;

export function renderVerifyPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify a dossier — kajaril</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#e5e5e5;padding:32px 18px;min-height:100vh;display:flex;align-items:flex-start;justify-content:center}
.card{background:#111;border:1px solid #1f1f1f;border-radius:14px;padding:24px;max-width:560px;width:100%}
h1{font-size:1.2rem;font-weight:600;letter-spacing:-0.01em;margin-bottom:8px}
.sub{font-size:0.85rem;color:#888;margin-bottom:18px;line-height:1.6}
#drop{border:2px dashed #2a2a2a;border-radius:12px;padding:34px 16px;text-align:center;color:#888;font-size:0.9rem;transition:border-color 0.15s,background 0.15s}
#drop.over{border-color:#16a34a;background:#0a2a14}
#drop label{display:inline-block;margin-top:10px;padding:10px 16px;border-radius:9px;background:#1a1a1a;border:1px solid #2a2a2a;color:#e5e5e5;font-weight:600;cursor:pointer;font-size:0.85rem}
#file{display:none}
#results{list-style:none;margin:18px 0 0;padding:0}
#results li{padding:10px 14px;border-radius:8px;font-size:0.85rem;margin-bottom:8px;line-height:1.5;word-break:break-word}
#results li.pass{background:#0a2a14;color:#86efac;border:1px solid #14532d}
#results li.fail{background:#2a0a0a;color:#fca5a5;border:1px solid #532d2d}
#results li.warn{background:#2a1a0a;color:#fcd34d;border:1px solid #533a14}
.verdict{margin-top:14px;padding:16px;border-radius:9px;font-size:0.92rem;font-weight:600;text-align:center;display:none}
.verdict.pass{display:block;background:#0a2a14;color:#86efac;border:1px solid #14532d}
.verdict.fail{display:block;background:#2a0a0a;color:#fca5a5;border:1px solid #532d2d}
.verdict.warn{display:block;background:#2a1a0a;color:#fcd34d;border:1px solid #533a14}
.verdict.checking{display:block;background:#1a1a1a;color:#a8a8a8;border:1px solid #2a2a2a}
.note{font-size:0.75rem;color:#666;margin-top:18px;line-height:1.6}
.foot{font-size:0.72rem;color:#555;margin-top:22px;text-align:center}
.foot a{color:#777;text-decoration:none}
</style>
</head>
<body>
<div class="card">
  <h1>Verify a dossier</h1>
  <div class="sub">Drop a kajaril evidence file (<code>.jsonl</code>) below. Your browser recomputes every
  tamper-evident fingerprint and checks the notary's Ed25519 signatures against the published
  key — nothing is uploaded anywhere.</div>
  <div id="drop">
    Drag &amp; drop the dossier file here
    <br>
    <label for="file">or choose a file</label>
    <input type="file" id="file" accept=".jsonl,application/x-ndjson,application/json,text/plain">
  </div>
  <ul id="results"></ul>
  <div id="verdict" class="verdict"></div>
  <div class="note">The notary public key is served at
  <code>/.well-known/notary-pubkey</code>. Verification needs a current browser with
  Ed25519 support (Chrome, Firefox, Safari — all current versions).</div>
  <div class="foot">— <a href="https://kajaril.com">kajaril</a> · the neutral witness for agent actions</div>
</div>
<script src="/verify.js"></script>
</body>
</html>`;
}
