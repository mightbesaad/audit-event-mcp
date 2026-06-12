import { isValidClientIdShape } from "@/lib/approval";

// M2M client-credentials auth (decision D2): the REST/production surface for agents that
// cannot do a browser OAuth flow. Hand-rolled on Web Crypto — no new dependency (Day-0
// supply-chain rule). Two grants exist per tenant, issued separately:
//   agent — request/poll approvals, record events. Cannot read chains or export dossiers.
//   admin — everything.
//
// Client secrets are 32 bytes of CSPRNG output behind a scope-telling prefix
// (kjr_agent_… / kjr_admin_…). Only their SHA-256 hash is stored, in the tenant's own
// AuditDO (credentials table) — there is no central registry, no master that can derive a
// tenant's secret (deliberately NOT the D9 HKDF pattern: webhook secrets must be
// re-obtainable through the API, client secrets must not be), and rotating one tenant's
// scope never touches anyone else.
//
// Access tokens are short-lived HS256 JWTs signed with the M2M_TOKEN_SIGNING_SECRET
// Workers Secret. They are stateless and cannot be revoked before exp — the 1 h TTL bounds
// the exposure; rotating the signing secret invalidates every outstanding token at once.

export type M2MScope = "agent" | "admin";

export const M2M_SCOPES: readonly M2MScope[] = ["agent", "admin"];

export function isM2MScope(value: unknown): value is M2MScope {
  return value === "agent" || value === "admin";
}

export const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const TOKEN_ISSUER = "audit-event-mcp";
// Real tokens are ~300 chars; anything bigger is garbage and refused before crypto work.
const MAX_ACCESS_TOKEN_CHARS = 2048;
// Our secrets are 53 chars (prefix + 43). The cap only bounds hashing work on hostile input.
export const MAX_CLIENT_SECRET_CHARS = 256;

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

export function generateClientSecret(scope: M2MScope): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `kjr_${scope}_${base64UrlEncode(bytes)}`;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time comparison over fixed-length hex strings (same pattern as webhook.ts).
// Both sides here are SHA-256 digests, so length is fixed and the loop never early-exits.
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
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

export interface AccessTokenClaims {
  clientId: string;
  scope: M2MScope;
}

export async function mintAccessToken(
  signingSecret: string,
  claims: AccessTokenClaims,
  nowMs: number = Date.now(),
): Promise<string> {
  if (!signingSecret) throw new Error("token signing secret is empty");
  if (!isValidClientIdShape(claims.clientId)) throw new Error("invalid clientId");
  if (!isM2MScope(claims.scope)) throw new Error("invalid scope");

  const iat = Math.floor(nowMs / 1000);
  const jti = new Uint8Array(16);
  crypto.getRandomValues(jti);
  const header = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })),
  );
  const payload = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        iss: TOKEN_ISSUER,
        sub: claims.clientId,
        scope: claims.scope,
        iat,
        exp: iat + ACCESS_TOKEN_TTL_SECONDS,
        jti: base64UrlEncode(jti),
      }),
    ),
  );
  const key = await hmacKey(signingSecret, "sign");
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${base64UrlEncode(new Uint8Array(sig))}`;
}

// Returns the claims only if the signature verifies AND the header is exactly our format
// (alg pinned to HS256 — a token claiming any other alg, including "none", is refused
// before any key material is touched) AND iss/sub/scope/exp all check out. Any failure →
// null; callers respond with a uniform 401.
export async function verifyAccessToken(
  signingSecret: string,
  token: string,
  nowMs: number = Date.now(),
): Promise<AccessTokenClaims | null> {
  if (!signingSecret || typeof token !== "string" || token.length > MAX_ACCESS_TOKEN_CHARS) {
    return null;
  }

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  const headerBytes = base64UrlDecode(headerB64);
  const payloadBytes = base64UrlDecode(payloadB64);
  const sigBytes = base64UrlDecode(sigB64);
  if (!headerBytes || !payloadBytes || !sigBytes) return null;

  let header: { alg?: unknown; typ?: unknown };
  try {
    header = JSON.parse(new TextDecoder().decode(headerBytes));
  } catch {
    return null;
  }
  if (header.alg !== "HS256" || header.typ !== "JWT") return null;

  try {
    const key = await hmacKey(signingSecret, "verify");
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes as unknown as BufferSource,
      new TextEncoder().encode(`${headerB64}.${payloadB64}`),
    );
    if (!valid) return null;
  } catch {
    return null;
  }

  let payload: { iss?: unknown; sub?: unknown; scope?: unknown; exp?: unknown };
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }

  if (payload.iss !== TOKEN_ISSUER) return null;
  if (typeof payload.sub !== "string" || !isValidClientIdShape(payload.sub)) return null;
  if (!isM2MScope(payload.scope)) return null;
  if (typeof payload.exp !== "number" || !Number.isInteger(payload.exp)) return null;
  if (payload.exp * 1000 < nowMs) return null;

  return { clientId: payload.sub, scope: payload.scope };
}
