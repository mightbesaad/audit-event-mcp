import type { DatabaseSync } from "node:sqlite";
import * as ed from "@noble/ed25519";
import { beforeAll, describe, expect, it } from "vitest";
import { AuditDO } from "@/do";
import goWorker from "@/go";
import type { DossierFetchResult, DossierInternalClient } from "@/lib/dossier";
import { buildMerkleRoot } from "@/lib/hash";
import type { DossierResult, GoEnv } from "@/lib/types";
import { VERIFY_SCRIPT } from "@/lib/verify-page";
// `cloudflare:workers` is aliased to test/stubs/cloudflare-workers.ts in vitest.config.ts
import { DossierInternal } from "@/main";
import { fakeEnv, makeMockR2, makeState, post } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

// Same SubtleCrypto wiring the real notary worker uses (src/notary.ts).
ed.etc.sha512Async = async (...msgs: Uint8Array[]) =>
  new Uint8Array(await crypto.subtle.digest("SHA-512", ed.etc.concatBytes(...msgs)));

const NOTARY_PRIV = "4e".repeat(32);
let NOTARY_PUB_HEX = "";

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// A notary that REALLY signs, mirroring src/notary.ts /sign — so what the verifier checks
// in these tests is byte-for-byte what production produces.
function makeSigningNotary(): Fetcher {
  return {
    async fetch(_url: RequestInfo | URL, init?: RequestInit) {
      const { events } = JSON.parse(String(init?.body)) as {
        events: Array<{ id: string; chainHash: string }>;
      };
      const merkleRoot = await buildMerkleRoot(events);
      const notarySig = bytesToHex(await ed.signAsync(merkleRoot, NOTARY_PRIV));
      return Response.json({ merkleRoot, notarySig });
    },
  } as unknown as Fetcher;
}

beforeAll(async () => {
  NOTARY_PUB_HEX = bytesToHex(await ed.getPublicKeyAsync(NOTARY_PRIV));
});

// The verifier under test is the exact script the worker serves at /verify.js: the DOM
// glue is skipped (no `document` in Node), the pure core is returned for direct calls.
type VerifyReport = {
  parse: { ok: boolean; count: number };
  fingerprints: { checked: number; passed: number; failed: string[]; uncheckable: number };
  linkage: { linked: number };
  notary: {
    claimedRecords: number;
    attestedRecords: number;
    roots: number;
    verifiedRoots: number;
    failedRoots: string[];
    brokenInclusion: string[];
    unattestedIds: string[];
    keyUsable: boolean;
  };
  verdict: string;
};
type VerifyFn = (text: string, pubkeyHex: string, subtle: SubtleCrypto) => Promise<VerifyReport>;

const verifyDossier = new Function(`${VERIFY_SCRIPT}; return kajarilVerifyDossier;`)() as VerifyFn;

const BASE_EVENT = {
  eventType: "tool.call" as const,
  purpose: "unit test",
  sessionId: "s-test",
  agentId: "agent-test",
};
const DOSSIER_HEADERS = { "X-Client-Id": "client-test", "X-Base-Url": "https://go.example.com" };

// Records a small real chain for one subject, optionally notarizes it, exports the
// dossier, and returns the stored JSONL.
async function buildDossierFixture(opts: { notarize: boolean }): Promise<{
  jsonl: string;
  db: DatabaseSync;
}> {
  const db = new DBSync(":memory:");
  const r2 = makeMockR2();
  const env = {
    ...fakeEnv,
    AUDIT_PAYLOADS: r2,
    ...(opts.notarize ? { NOTARY: makeSigningNotary() } : {}),
  };
  const do_ = new AuditDO(makeState(db), env);

  for (const [i, event] of [
    { ...BASE_EVENT, subjectId: "user-1", input: { step: 1 } },
    { ...BASE_EVENT, subjectId: "user-1", inputHashOmittedReason: "no_personal_data" },
    { ...BASE_EVENT, subjectId: "user-1", eventType: "decision.made" as const, input: { ok: 1 } },
  ].entries()) {
    const res = await do_.fetch(post("/record", event));
    expect(res.status, `record #${i}`).toBe(200);
  }
  if (opts.notarize) await do_.alarm();

  const dossierRes = await do_.fetch(post("/dossier", { subjectId: "user-1" }, DOSSIER_HEADERS));
  expect(dossierRes.status).toBe(200);
  const { url } = (await dossierRes.json()) as DossierResult;
  const token = url.split("/").pop() as string;
  const obj = await (
    r2 as unknown as { get: (k: string) => Promise<{ text(): Promise<string> }> }
  ).get(`dossier/client-test/${token}.jsonl`);
  expect(obj).not.toBeNull();
  return { jsonl: await obj.text(), db };
}

describe("the /verify.js core — against real chains and real signatures", () => {
  it("verifies an untampered, notarized dossier end-to-end", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const report = await verifyDossier(jsonl, NOTARY_PUB_HEX, crypto.subtle);
    expect(report.parse).toEqual({ ok: true, count: 3 });
    expect(report.fingerprints.passed).toBe(3);
    expect(report.fingerprints.failed).toEqual([]);
    expect(report.fingerprints.uncheckable).toBe(0);
    // Subject-filtered but contiguous here, so linkage spans the whole export.
    expect(report.linkage.linked).toBe(2);
    expect(report.notary.attestedRecords).toBe(3);
    expect(report.notary.verifiedRoots).toBe(report.notary.roots);
    expect(report.notary.failedRoots).toEqual([]);
    expect(report.verdict).toBe("verified");
    db.close();
  });

  it("reports an unnotarized dossier as internally consistent but unattested", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: false });
    const report = await verifyDossier(jsonl, NOTARY_PUB_HEX, crypto.subtle);
    expect(report.fingerprints.passed).toBe(3);
    expect(report.notary.roots).toBe(0);
    expect(report.verdict).toBe("unattested");
    db.close();
  });

  it("catches a tampered field — the fingerprint no longer recomputes", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const tampered = jsonl.replace('"purpose":"unit test"', '"purpose":"totally innocent"');
    expect(tampered).not.toBe(jsonl);
    const report = await verifyDossier(tampered, NOTARY_PUB_HEX, crypto.subtle);
    // purpose is not part of the chain preimage — but event_type is:
    const typeTampered = jsonl.replace('"event_type":"decision.made"', '"event_type":"tool.call"');
    const typeReport = await verifyDossier(typeTampered, NOTARY_PUB_HEX, crypto.subtle);
    expect(typeReport.fingerprints.failed.length).toBe(1);
    expect(typeReport.verdict).toBe("failed");
    // and a swapped input_hash breaks too:
    const hashTampered = jsonl.replace(/"input_hash":"[0-9a-f]{8}/, '"input_hash":"deadbeef');
    const hashReport = await verifyDossier(hashTampered, NOTARY_PUB_HEX, crypto.subtle);
    expect(hashReport.verdict).toBe("failed");
    // sanity: the purpose-only tamper passes fingerprints (purpose is witnessed via the
    // input hash of approval flows, not the chain preimage) — documented behavior.
    expect(report.fingerprints.failed).toEqual([]);
    db.close();
  });

  it("catches a forged notary signature", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const forged = jsonl.replace(/"notary_sig":"[0-9a-f]{4}/g, '"notary_sig":"ffff');
    const report = await verifyDossier(forged, NOTARY_PUB_HEX, crypto.subtle);
    expect(report.notary.failedRoots.length).toBeGreaterThan(0);
    expect(report.verdict).toBe("failed");
    db.close();
  });

  it("fails signatures checked against the wrong published key", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const wrongKey = bytesToHex(await ed.getPublicKeyAsync("77".repeat(32)));
    const report = await verifyDossier(jsonl, wrongKey, crypto.subtle);
    expect(report.verdict).toBe("failed");
    db.close();
  });

  it("degrades to unverifiable — never a false verdict — when the key is unusable", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const report = await verifyDossier(jsonl, "", crypto.subtle);
    expect(report.notary.keyUsable).toBe(false);
    expect(report.verdict).toBe("unverifiable");
    db.close();
  });

  it("includes a Merkle inclusion proof on every notarized record", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const rows = jsonl
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const row of rows) {
      expect(Array.isArray(row.merkle_proof)).toBe(true);
    }
    db.close();
  });

  // THE attack the inclusion proof exists to stop (Day-5 security fix): an attacker borrows a
  // genuine (merkle_root, notary_sig) pair from any real dossier and staples it onto records
  // they fabricated — every chain-preimage field is public, so the fingerprints recompute and
  // the signature is genuine. Only the inclusion proof exposes the forgery: the fabricated
  // leaf is not under the signed root.
  it("rejects a genuine notary signature stapled onto fabricated records", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const real = jsonl
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .find((r) => r.merkle_root && r.notary_sig) as Record<string, unknown>;

    const sha256Hex = async (text: string) =>
      Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))),
      )
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    const fabId = "fabricated-evidence-0001";
    const slot = "00".repeat(32);
    const fabChain = await sha256Hex(`${fabId}|tool.call|${slot}|`); // matches computeChainHash
    const fabricated = {
      id: fabId,
      agent_id: "attacker",
      session_id: "s",
      event_type: "tool.call",
      input_hash: slot,
      input_hash_omitted_reason: null,
      lawful_basis: null,
      purpose: "transfer 1,000,000 — totally approved",
      subject_id: "victim",
      retention_days: 365,
      prev_hash: null,
      chain_hash: fabChain,
      merkle_root: real.merkle_root,
      notary_sig: real.notary_sig,
      created_at: "2026-06-13T00:00:00.000Z",
    };

    // (a) borrowed sig, NO proof
    const noProof = await verifyDossier(
      `${JSON.stringify(fabricated)}\n`,
      NOTARY_PUB_HEX,
      crypto.subtle,
    );
    expect(noProof.fingerprints.failed).toEqual([]); // self-consistent — fingerprints alone are fooled
    expect(noProof.notary.failedRoots).toEqual([]); // the borrowed signature really is genuine
    expect(noProof.notary.brokenInclusion).toContain(fabId); // …but the record is not in that batch
    expect(noProof.notary.attestedRecords).toBe(0);
    expect(noProof.verdict).toBe("failed");

    // (b) borrowed sig + a bogus inclusion proof
    const bogusProof = await verifyDossier(
      `${JSON.stringify({ ...fabricated, merkle_proof: [{ hash: "aa".repeat(32), left: false }] })}\n`,
      NOTARY_PUB_HEX,
      crypto.subtle,
    );
    expect(bogusProof.notary.brokenInclusion).toContain(fabId);
    expect(bogusProof.verdict).toBe("failed");
    db.close();
  });

  // THE mixed-file variant the inclusion-proof fix alone does NOT stop (caught in re-review,
  // missed by the self-review): an attacker appends fabricated rows carrying NO signature — so
  // they are never inclusion-checked — to a genuine, fully-attested dossier. Fingerprints pass
  // and the real rows are attested; under the old logic (attestedRecords > 0) that was a green
  // "verified". The verdict must instead be "partially_attested", naming the un-notarized rows.
  it("does not green-light fabricated un-notarized rows riding a genuine attested dossier", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const genuine = jsonl.trim().split("\n");

    const sha256Hex = async (text: string) =>
      Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))),
      )
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    const fabId = "fabricated-rider-0001";
    const slot = "11".repeat(32);
    const fabChain = await sha256Hex(`${fabId}|tool.call|${slot}|`); // matches computeChainHash
    const fabricated = {
      id: fabId,
      agent_id: "attacker",
      session_id: "s",
      event_type: "tool.call",
      input_hash: slot,
      input_hash_omitted_reason: null,
      lawful_basis: null,
      purpose: "transfer 1,000,000 — totally approved",
      subject_id: "user-1",
      retention_days: 365,
      prev_hash: null,
      chain_hash: fabChain,
      // deliberately NO merkle_root / notary_sig — rides as an "un-notarized" row
      created_at: "2026-06-13T00:00:00.000Z",
    };

    const mixed = `${genuine.join("\n")}\n${JSON.stringify(fabricated)}\n`;
    const report = await verifyDossier(mixed, NOTARY_PUB_HEX, crypto.subtle);

    expect(report.parse.count).toBe(4);
    expect(report.fingerprints.failed).toEqual([]); // the fabricated row is self-consistent
    expect(report.notary.brokenInclusion).toEqual([]); // it never claims a root, so never "broken"
    expect(report.notary.attestedRecords).toBe(3); // only the genuine rows
    expect(report.notary.unattestedIds).toContain(fabId);
    expect(report.verdict).toBe("partially_attested"); // NOT "verified"
    db.close();
  });

  // Duplicate-id hardening (re-review): the rider reuses a GENUINE row's id instead of a fresh
  // one. The verdict was already safe (count-based), but unattestedIds must be computed by row,
  // not id-membership — otherwise the rider hides and the green "all attested" tick fires above
  // the yellow banner. Assert the row-accurate invariant.
  it("flags an un-notarized rider even when it reuses a genuine row's id", async () => {
    const { jsonl, db } = await buildDossierFixture({ notarize: true });
    const genuine = jsonl.trim().split("\n");
    const stolenId = (JSON.parse(genuine[0] as string) as { id: string }).id;

    const sha256Hex = async (text: string) =>
      Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))),
      )
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    const slot = "22".repeat(32);
    const fabChain = await sha256Hex(`${stolenId}|tool.call|${slot}|`);
    const rider = {
      id: stolenId, // reuses a genuine, attested row's id
      agent_id: "attacker",
      session_id: "s",
      event_type: "tool.call",
      input_hash: slot,
      input_hash_omitted_reason: null,
      lawful_basis: null,
      purpose: "transfer 1,000,000 — totally approved",
      subject_id: "user-1",
      retention_days: 365,
      prev_hash: null,
      chain_hash: fabChain,
      created_at: "2026-06-13T00:00:00.000Z",
    };

    const mixed = `${genuine.join("\n")}\n${JSON.stringify(rider)}\n`;
    const report = await verifyDossier(mixed, NOTARY_PUB_HEX, crypto.subtle);

    expect(report.parse.count).toBe(4);
    expect(report.notary.attestedRecords).toBe(3);
    // strictly less → the green "all attested" tick stays yellow, not a contradictory green ✓
    expect(report.notary.attestedRecords).toBeLessThan(report.parse.count);
    // row-accurate, not id-membership: one unproven row even though its id collides
    expect(report.notary.unattestedIds.length).toBe(report.parse.count - report.notary.attestedRecords);
    expect(report.notary.unattestedIds).toContain(stolenId);
    expect(report.verdict).toBe("partially_attested");
    db.close();
  });

  it("never throws on garbage input", async () => {
    for (const garbage of ["", "not json", '{"id": 1}', "[1,2,3]", " "]) {
      const report = await verifyDossier(garbage, NOTARY_PUB_HEX, crypto.subtle);
      expect(report.parse.ok).toBe(false);
      expect(report.verdict).toBe("invalid");
    }
  });
});

describe("DossierInternal entrypoint", () => {
  const TOKEN = "ab".repeat(32);

  function makeEntry(r2: R2Bucket | undefined): DossierInternal {
    return new DossierInternal(
      {} as ExecutionContext,
      {
        ...fakeEnv,
        AUDIT_PAYLOADS: r2,
      } as never,
    );
  }

  it("serves a stored dossier by capability token", async () => {
    const r2 = makeMockR2();
    await r2.put(`dossier/client-test/${TOKEN}.jsonl`, '{"id":"x"}\n', {
      customMetadata: {
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        subjectId: "user-1",
      },
    });
    const result = await makeEntry(r2).getDossier("client-test", TOKEN);
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.body).toContain('"id":"x"');
      expect(result.subjectId).toBe("user-1");
    }
  });

  it("expires on read and deletes the object", async () => {
    const r2 = makeMockR2();
    const key = `dossier/client-test/${TOKEN}.jsonl`;
    await r2.put(key, "x", {
      customMetadata: { expiresAt: new Date(Date.now() - 1000).toISOString() },
    });
    const entry = makeEntry(r2);
    expect((await entry.getDossier("client-test", TOKEN)).status).toBe("expired");
    expect((await entry.getDossier("client-test", TOKEN)).status).toBe("not_found");
  });

  it("shape-checks both segments before touching storage", async () => {
    const r2 = makeMockR2();
    const entry = makeEntry(r2);
    expect((await entry.getDossier("../escape", TOKEN)).status).toBe("not_found");
    expect((await entry.getDossier("client-test", "short")).status).toBe("not_found");
    expect((await entry.getDossier("client-test", "Z".repeat(64))).status).toBe("not_found");
  });

  it("reports unavailable without R2", async () => {
    expect((await makeEntry(undefined).getDossier("client-test", TOKEN)).status).toBe(
      "unavailable",
    );
  });
});

describe("go worker — dossier pages and /verify", () => {
  const TOKEN = "cd".repeat(32);

  function goEnv(overrides: Partial<GoEnv> = {}): GoEnv {
    return {
      AUDIT: {} as GoEnv["AUDIT"],
      DOSSIER: {
        getDossier: async (): Promise<DossierFetchResult> => ({ status: "not_found" }),
      } as DossierInternalClient,
      ...overrides,
    } as GoEnv;
  }

  function dossierClient(result: DossierFetchResult): DossierInternalClient {
    return { getDossier: async () => result };
  }

  async function get(env: GoEnv, path: string): Promise<Response> {
    return goWorker.fetch(new Request(`https://go.kajaril.com${path}`), env, {} as never);
  }

  const OK_RESULT: DossierFetchResult = {
    status: "ok",
    body: `${JSON.stringify({
      id: "evt-1",
      agent_id: "agent-<img src=x onerror=alert(1)>",
      session_id: "s-1",
      event_type: "tool.call",
      input_hash: "aa".repeat(32),
      input_hash_omitted_reason: null,
      lawful_basis: "contract",
      purpose: 'hostile <script>alert("purpose")</script>',
      subject_id: "user-1",
      retention_days: 365,
      prev_hash: null,
      chain_hash: "bb".repeat(32),
      merkle_root: "cc".repeat(32),
      notary_sig: "dd".repeat(64),
      created_at: "2026-06-13T10:00:00.000Z",
    })}\n`,
    subjectId: "user-1",
    expiresAt: null,
  };

  it("renders the human-readable dossier with hostile fields escaped", async () => {
    const env = goEnv({ DOSSIER: dossierClient(OK_RESULT) });
    const res = await get(env, `/dossier/client-test/${TOKEN}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Security-Policy")).toContain("script-src 'none'");
    const html = await res.text();
    expect(html).toContain("Audit dossier");
    expect(html).toContain("user-1");
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("Verify this dossier");
  });

  it("serves the raw JSONL as an attachment", async () => {
    const env = goEnv({ DOSSIER: dossierClient(OK_RESULT) });
    const res = await get(env, `/dossier/client-test/${TOKEN}/raw`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/x-ndjson");
    expect(res.headers.get("Content-Disposition")).toContain(".jsonl");
    expect(await res.text()).toBe(OK_RESULT.status === "ok" ? OK_RESULT.body : "");
  });

  it("404s malformed segments without consulting the binding", async () => {
    let called = 0;
    const env = goEnv({
      DOSSIER: {
        getDossier: async () => {
          called++;
          return { status: "ok", body: "", subjectId: null, expiresAt: null };
        },
      },
    });
    for (const path of [
      "/dossier/../escape/aa",
      `/dossier/client%2Ftest/${TOKEN}`,
      "/dossier/client-test/nothex",
    ]) {
      const res = await get(env, path);
      expect(res.status, path).toBe(404);
    }
    expect(called).toBe(0);
  });

  it("renders expired (410) and unconfigured (503) states", async () => {
    expect(
      (await get(goEnv({ DOSSIER: dossierClient({ status: "expired" }) }), `/dossier/c/${TOKEN}`))
        .status,
    ).toBe(410);
    expect((await get(goEnv({ DOSSIER: undefined }), `/dossier/c/${TOKEN}`)).status).toBe(503);
  });

  it("serves /verify with script-from-self CSP and /verify.js with the verifier", async () => {
    const env = goEnv();
    const page = await get(env, "/verify");
    expect(page.status).toBe(200);
    const csp = page.headers.get("Content-Security-Policy") as string;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("connect-src 'self'");
    expect(await page.text()).toContain('src="/verify.js"');

    const script = await get(env, "/verify.js");
    expect(script.status).toBe(200);
    expect(script.headers.get("Content-Type")).toContain("javascript");
    expect(await script.text()).toContain("kajarilVerifyDossier");
  });

  it("proxies the notary pubkey same-origin and fails closed without the binding", async () => {
    const notary = {
      fetch: async () => Response.json({ algorithm: "Ed25519", publicKey: NOTARY_PUB_HEX }),
    } as unknown as Fetcher;
    const ok = await get(goEnv({ NOTARY: notary }), "/.well-known/notary-pubkey");
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { publicKey: string }).publicKey).toBe(NOTARY_PUB_HEX);

    const missing = await get(goEnv(), "/.well-known/notary-pubkey");
    expect(missing.status).toBe(503);
  });
});
