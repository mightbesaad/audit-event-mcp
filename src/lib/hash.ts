async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function computeInputHash(input: unknown): Promise<string> {
  return sha256Hex(JSON.stringify(input));
}

// Canonical JSON: object keys sorted recursively, arrays in order, JSON semantics for
// primitives (undefined object values dropped, NaN/Infinity → null). input_hash keeps plain
// JSON.stringify (chain format frozen, D7); action_payload_hash needs canonical form because
// an auditor re-verifies it from the payload *document*, not from our original byte stream —
// the hash must survive any JSON round-trip that reorders keys (decision D6).
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`);
  return `{${entries.join(",")}}`;
}

export async function computeActionPayloadHash(payload: unknown): Promise<string> {
  return sha256Hex(canonicalJson(payload));
}

export async function computeChainHash(params: {
  id: string;
  eventType: string;
  inputHashSlot: string;
  prevHash: string | null;
}): Promise<string> {
  const { id, eventType, inputHashSlot, prevHash } = params;
  return sha256Hex(`${id}|${eventType}|${inputHashSlot}|${prevHash ?? ""}`);
}

// Builds a SHA-256 binary Merkle root over a set of audit events.
// Leaves are sorted by id ascending; odd layers duplicate the last node.
export async function buildMerkleRoot(
  leaves: Array<{ id: string; chainHash: string }>,
): Promise<string> {
  if (leaves.length === 0) throw new Error("empty leaves");
  const sorted = [...leaves].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  let layer: string[] = await Promise.all(
    sorted.map((leaf) => sha256Hex(`${leaf.id}|${leaf.chainHash}`)),
  );
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      if (left === undefined) break;
      const right = layer[i + 1] ?? left;
      next.push(await sha256Hex(left + right));
    }
    layer = next;
  }
  const root = layer[0];
  if (root === undefined) throw new Error("empty layer");
  return root;
}
