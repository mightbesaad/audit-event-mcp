import * as ed from "@noble/ed25519";
import { Hono } from "hono";
import { buildMerkleRoot } from "@/lib/hash";

// Workers has no native sync sha512 — configure noble to use SubtleCrypto.
ed.etc.sha512Async = async (...msgs: Uint8Array[]) =>
  new Uint8Array(await crypto.subtle.digest("SHA-512", ed.etc.concatBytes(...msgs)));

interface NotaryEnv {
  NOTARY_PRIVATE_KEY?: string;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const app = new Hono<{ Bindings: NotaryEnv }>();

// Auditors fetch this to verify notary_sig fields offline.
app.get("/.well-known/notary-pubkey", async (c) => {
  const privateKeyHex = c.env.NOTARY_PRIVATE_KEY;
  if (!privateKeyHex) {
    return c.json({ error: "Notary not configured" }, 503);
  }
  const publicKey = await ed.getPublicKeyAsync(privateKeyHex);
  return c.json({ algorithm: "Ed25519", publicKey: bytesToHex(publicKey) }, 200, {
    "Cache-Control": "public, max-age=3600",
  });
});

// Called exclusively via CF service binding from AuditDO.alarm().
// Platform auth guarantees only same-account Workers can reach this.
app.post("/sign", async (c) => {
  const privateKeyHex = c.env.NOTARY_PRIVATE_KEY;
  if (!privateKeyHex) {
    return c.json({ error: "Notary not configured" }, 503);
  }
  const { events } = await c.req.json<{
    events: Array<{ id: string; chainHash: string }>;
  }>();
  if (!Array.isArray(events) || events.length === 0) {
    return c.json({ error: "events required" }, 400);
  }
  const merkleRoot = await buildMerkleRoot(events);
  const signature = await ed.signAsync(merkleRoot, privateKeyHex);
  return c.json({ merkleRoot, notarySig: bytesToHex(signature) });
});

export default { fetch: app.fetch };
