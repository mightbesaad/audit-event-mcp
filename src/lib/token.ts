import { isValidApprovalIdShape, isValidClientIdShape } from "@/lib/approval";

// Approval link token (decision D3): the ONLY routing input for the public approve page.
// Format: v1.<base64url(JSON {c,a,e})>.<base64url(HMAC-SHA256 over "v1.<payload>")>
//
// The signature covers the version prefix, so a future v2 can change the payload layout
// without v1 signatures validating against it. Verification answers the public-link routing
// problem: nothing user-supplied may select a tenant — client_id only ever leaves a token
// whose signature checked out, and the DO name is derived server-side from that.

export interface ApprovalTokenPayload {
  clientId: string;
  approvalId: string;
  /** Unix epoch seconds. Should outlive the approval's expires_at (plus grace) so the
   *  approve page can still render terminal states instead of "invalid link". */
  exp: number;
}

const TOKEN_VERSION = "v1";
// Generous upper bound — real tokens are ~150-300 chars. Anything bigger is garbage
// and gets refused before any crypto work.
const MAX_TOKEN_CHARS = 1024;

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const padded = s
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(s.length / 4) * 4, "=");
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
}

async function hmacKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

export async function mintApprovalToken(
  secret: string,
  payload: ApprovalTokenPayload,
): Promise<string> {
  if (!secret) throw new Error("token secret is empty");
  if (!isValidClientIdShape(payload.clientId)) throw new Error("invalid clientId");
  if (!isValidApprovalIdShape(payload.approvalId)) throw new Error("invalid approvalId");
  if (!Number.isInteger(payload.exp) || payload.exp <= 0) throw new Error("invalid exp");

  const body = JSON.stringify({ c: payload.clientId, a: payload.approvalId, e: payload.exp });
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(body));
  const signedPart = `${TOKEN_VERSION}.${payloadB64}`;
  const key = await hmacKey(secret, "sign");
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPart));
  return `${signedPart}.${base64UrlEncode(new Uint8Array(sig))}`;
}

// Returns the payload only if the signature verifies AND the token is unexpired AND both
// ids have valid shapes. Any failure → null; callers render a uniform not-found. Signature
// comparison happens inside crypto.subtle.verify, which is constant-time.
export async function verifyApprovalToken(
  secret: string,
  token: string,
  now: number = Date.now(),
): Promise<ApprovalTokenPayload | null> {
  if (!secret || typeof token !== "string" || token.length > MAX_TOKEN_CHARS) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [version, payloadB64, sigB64] = parts as [string, string, string];
  if (version !== TOKEN_VERSION) return null;

  const sigBytes = base64UrlDecode(sigB64);
  const payloadBytes = base64UrlDecode(payloadB64);
  if (!sigBytes || !payloadBytes) return null;

  try {
    const key = await hmacKey(secret, "verify");
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes as unknown as BufferSource,
      new TextEncoder().encode(`${version}.${payloadB64}`),
    );
    if (!valid) return null;
  } catch {
    return null;
  }

  let parsed: { c?: unknown; a?: unknown; e?: unknown };
  try {
    parsed = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }

  const { c, a, e } = parsed;
  if (typeof c !== "string" || !isValidClientIdShape(c)) return null;
  if (typeof a !== "string" || !isValidApprovalIdShape(a)) return null;
  if (typeof e !== "number" || !Number.isInteger(e)) return null;
  if (e * 1000 < now) return null;

  return { clientId: c, approvalId: a, exp: e };
}
