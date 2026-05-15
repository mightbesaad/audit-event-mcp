import { Hono } from "hono";

// Notary Worker — Merkle batch flush + Ed25519 signing.
// Full implementation deferred to M8-next.
// Deploy: wrangler deploy --config wrangler.notary.jsonc
// Secret: wrangler secret put NOTARY_PRIVATE_KEY --config wrangler.notary.jsonc

interface NotaryEnv {
  NOTARY_PRIVATE_KEY?: string;
}

const app = new Hono<{ Bindings: NotaryEnv }>();

// Unauthenticated, cacheable (1h). Auditors fetch this to verify notary_sig fields.
app.get("/.well-known/notary-pubkey", (_c) => {
  // TODO(M8-next): derive public key from NOTARY_PRIVATE_KEY secret and return it
  return Response.json({ error: "Notary not yet configured" }, { status: 503 });
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, _env: NotaryEnv, _ctx: ExecutionContext): Promise<void> {
    // TODO(M8-next): collect pending { id, chain_hash } pairs from DOs
    //   → sort by id → binary Merkle tree → Ed25519 sign root → write back to DOs
  },
};
