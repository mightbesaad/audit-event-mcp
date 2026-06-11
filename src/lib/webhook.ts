// Decision webhook (D4) and its signing-secret design (D9).
//
// Per-tenant secret: whsec_ + base64url(HKDF-SHA256(master, salt="", info=v1-prefix+clientId)).
// No storage — derivable wherever the master Workers Secret is bound, and returned to the
// customer in every request_approval response, so there is nothing to look up and no
// dashboard needed in v1. Rotating the master rotates every tenant at once; customers
// self-heal by reading the next response. The versioned info prefix leaves room for
// per-tenant key versioning later without a format break.
//
// Signature: X-Kajaril-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "{t}.{body}")>.
// The HMAC key is the literal secret string's UTF-8 bytes (whsec_ prefix included) — no
// decode step for the receiver. Stripe-shaped on purpose; the timestamp is inside the
// signed material so a captured delivery cannot be replayed past the tolerance window.

export const WEBHOOK_SECRET_PREFIX = "whsec_";
export const WEBHOOK_SIGNATURE_HEADER = "X-Kajaril-Signature";
export const WEBHOOK_TOLERANCE_SECONDS = 300;
const DERIVE_INFO_PREFIX = "kajaril-webhook-v1:";
const DELIVERY_TIMEOUT_MS = 10_000;

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function deriveWebhookSecret(master: string, clientId: string): Promise<string> {
  if (!master) throw new Error("webhook master secret is empty");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(master),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(DERIVE_INFO_PREFIX + clientId),
    },
    key,
    256,
  );
  return WEBHOOK_SECRET_PREFIX + base64UrlEncode(new Uint8Array(bits));
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return hexEncode(new Uint8Array(sig));
}

export async function buildSignatureHeader(
  secret: string,
  body: string,
  nowMs: number = Date.now(),
): Promise<string> {
  const t = Math.floor(nowMs / 1000);
  const v1 = await hmacHex(secret, `${t}.${body}`);
  return `t=${t},v1=${v1}`;
}

// Reference verifier — what receivers implement on their side (documented in the README).
// Exported so the docs example and our tests are the same code path.
export async function verifyWebhookSignature(
  secret: string,
  header: string,
  body: string,
  nowMs: number = Date.now(),
  toleranceSeconds: number = WEBHOOK_TOLERANCE_SECONDS,
): Promise<boolean> {
  const match = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header);
  if (!match) return false;
  const [, tStr, v1] = match as unknown as [string, string, string];
  const t = Number(tStr);
  if (!Number.isSafeInteger(t)) return false;
  if (Math.abs(nowMs / 1000 - t) > toleranceSeconds) return false;
  const expected = await hmacHex(secret, `${t}.${body}`);
  // Constant-time comparison: XOR-accumulate over fixed-length hex strings.
  if (expected.length !== v1.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ v1.charCodeAt(i);
  }
  return diff === 0;
}

export interface DecisionWebhookBody {
  type: "approval.decided";
  approval: {
    id: string;
    agentId: string;
    sessionId: string;
    status: "approved" | "denied";
    reason: string | null;
    responderId: string | null;
    actionSummary: string;
    actionPayloadHash: string | null;
    createdAt: string;
    decidedAt: string | null;
    expiresAt: string;
  };
  // Pointer to the approval.decided chain event — the receiver can cite it as evidence.
  chainEvent: { id: string; chainHash: string } | null;
}

// Single attempt, fire-and-forget (runs under ctx.waitUntil): the webhook is the resume
// accelerator, polling is the contract. Retries/outbox are v1.5 (DEFERRED.md). Redirects
// are refused so the signed body can never be re-POSTed to a location we did not sign for.
export async function sendDecisionWebhook(params: {
  master: string;
  clientId: string;
  callbackUrl: string;
  body: DecisionWebhookBody;
}): Promise<void> {
  try {
    const secret = await deriveWebhookSecret(params.master, params.clientId);
    const raw = JSON.stringify(params.body);
    const signature = await buildSignatureHeader(secret, raw);
    const res = await fetch(params.callbackUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [WEBHOOK_SIGNATURE_HEADER]: signature,
      },
      body: raw,
      redirect: "error",
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.error(`decision webhook to ${params.callbackUrl} returned ${res.status}`);
    }
  } catch (e) {
    console.error(
      `decision webhook to ${params.callbackUrl} failed: ${e instanceof Error ? e.message : e}`,
    );
  }
}
