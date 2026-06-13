// Dossier domain: the wire contract between the gated worker's DossierInternal entrypoint
// (src/main.ts) and the public go worker's dossier pages (D1, Day 5), plus the exported
// JSONL row shape the human-readable rendering and the /verify page both consume.

// 32 bytes of CSPRNG output, hex — minted by dossierToken() in do.ts. The token is the
// authorization (a bearer capability to one subject's exported records), so the shape
// check is strict: anything else never reaches R2.
const DOSSIER_TOKEN_RE = /^[0-9a-f]{64}$/;

export function isValidDossierTokenShape(token: string): boolean {
  return typeof token === "string" && DOSSIER_TOKEN_RE.test(token);
}

// One line of the exported JSONL (do.ts handleDossier). payload_ref is never exported
// (locked privacy invariant); input_hash / input_hash_omitted_reason / prev_hash are the
// chain_hash preimage that makes a dossier independently re-verifiable (Day 5).
// merkle_proof is the inclusion path binding this record to its signed merkle_root — present
// only on notarized records (Day-5 security fix; see buildMerkleProofs).
export interface DossierRow {
  id: string;
  agent_id: string;
  session_id: string;
  event_type: string;
  input_hash: string | null;
  input_hash_omitted_reason: string | null;
  lawful_basis: string | null;
  purpose: string;
  subject_id: string | null;
  retention_days: number;
  prev_hash: string | null;
  chain_hash: string;
  merkle_root: string | null;
  notary_sig: string | null;
  merkle_proof?: import("@/lib/hash").MerkleProofStep[];
  created_at: string;
}

// Tolerant of blank lines, strict about rows: a dossier that does not parse cleanly is not
// rendered at all — a half-rendered evidence document is worse than an error page.
export function parseDossierJsonl(text: string): DossierRow[] | null {
  const rows: DossierRow[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let row: unknown;
    try {
      row = JSON.parse(line);
    } catch {
      return null;
    }
    const r = row as Partial<DossierRow> | null;
    if (
      r === null ||
      typeof r !== "object" ||
      typeof r.id !== "string" ||
      typeof r.event_type !== "string" ||
      typeof r.chain_hash !== "string" ||
      typeof r.created_at !== "string"
    ) {
      return null;
    }
    rows.push(r as DossierRow);
  }
  return rows;
}

export type DossierFetchResult =
  | {
      status: "ok";
      body: string;
      subjectId: string | null;
      expiresAt: string | null;
    }
  | { status: "expired" }
  | { status: "not_found" }
  | { status: "unavailable" };

// What the go worker may ask of the gated worker about dossiers — read one by capability
// token, nothing else. Mirrors ApprovalInternalClient's role for approvals.
export interface DossierInternalClient {
  getDossier(clientId: string, token: string): Promise<DossierFetchResult>;
}
