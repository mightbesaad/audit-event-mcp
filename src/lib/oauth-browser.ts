import {
  type AuthRequest,
  getOAuthApi,
  OAuthProvider,
  type OAuthProviderOptions,
} from "@cloudflare/workers-oauth-provider";
import { isValidClientIdShape } from "@/lib/approval";
import { isM2MScope, type M2MScope } from "@/lib/m2m";
import type { Env } from "@/lib/types";

// Browser-flow OAuth (decision D11): `workers-oauth-provider` 0.7.2 (pinned, PR #30) owns
// authorization-code + refresh-token issuance, DCR, and token storage; the hand-rolled D10
// client_credentials path in index.ts is untouched. One public POST /oauth/token exists —
// index.ts shims it by grant_type and forwards the library's grants here. The library is
// never the outer router: rate caps and error-vocabulary uniformity live at the shim
// (D11 conditions 1–2), and /mcp authentication stays in index.ts for all three lanes.
//
// The consent page is rendered by US (consent-page.ts) using the library's helpers — the
// library deliberately ships no UI for its authorizeEndpoint. Everything it stores lives in
// OAUTH_KV (D11 condition 6): clients, grants, token hashes. Props encrypted into each
// grant carry the ONLY tenant selector ({clientId, scope}), set at consent time from a
// CF Access JWT — never from anything the OAuth client sent.

export const BROWSER_FLOW_SCOPES: readonly M2MScope[] = ["agent", "admin"];

// Required by the provider's constructor, unreachable by construction: index.ts forwards
// only token/register/metadata requests into provider.fetch, none of which fall through
// to these handlers. Loud 500 (not 404) so a routing regression fails tests immediately.
const UNREACHABLE_HANDLER = {
  fetch: async (): Promise<Response> =>
    Response.json({ error: "oauth_provider_misrouted" }, { status: 500 }),
};

const oauthOptions: OAuthProviderOptions<Env> = {
  apiRoute: "/__oauth-provider-api-unreachable",
  apiHandler: UNREACHABLE_HANDLER,
  defaultHandler: UNREACHABLE_HANDLER,
  authorizeEndpoint: "/oauth/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  scopesSupported: [...BROWSER_FLOW_SCOPES],
  // OAuth 2.1 posture, matching D2: PKCE S256 only — "plain" offers no protection against
  // code interception, and every MCP client we care about does S256.
  allowPlainPKCE: false,
};

const provider = new OAuthProvider<Env>(oauthOptions);

// Forwards a request to the library router. Callers are responsible for (a) having applied
// the shim's rate caps first and (b) checking env.OAUTH_KV is bound — the library throws
// raw TypeErrors without it, which must surface as our uniform 503, not a 500.
export async function forwardToOAuthProvider(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  return provider.fetch(request, env, ctx);
}

// What consent stored in the grant's encrypted props. Decrypted only by a presented valid
// token (the wrapping key travels inside the token string), so these claims are
// tamper-evident: nothing user-supplied selects a tenant (D1/D3 law, third lane).
interface BrowserTokenProps {
  clientId?: unknown;
  scope?: unknown;
}

export interface BrowserTokenAuth {
  clientId: string;
  scope: M2MScope;
}

// Resolves a library-issued opaque access token (shape: userId:grantId:secret) to the
// tenant + scope bound at consent. Returns null for anything that does not verify —
// callers respond with the same uniform 401 as the other Bearer lane.
export async function unwrapBrowserToken(
  env: Env,
  token: string,
): Promise<BrowserTokenAuth | null> {
  let summary: Awaited<ReturnType<ReturnType<typeof getOAuthApi>["unwrapToken"]>>;
  try {
    summary = await getOAuthApi(oauthOptions, env).unwrapToken<BrowserTokenProps>(token);
  } catch {
    return null;
  }
  if (!summary) return null;
  const props = summary.grant.props as BrowserTokenProps | null | undefined;
  const clientId = props?.clientId;
  const scope = props?.scope;
  if (typeof clientId !== "string" || !isValidClientIdShape(clientId)) return null;
  if (!isM2MScope(scope)) return null;
  // The token's userId segment keys the KV records; consent set it to the same tenant as
  // props.clientId. Disagreement means tampered storage — refuse.
  if (summary.userId !== clientId) return null;
  return { clientId, scope };
}

// Library helpers for the consent flow (parseAuthRequest, lookupClient,
// completeAuthorization). Constructed per request — construction is options validation
// only; all state lives in OAUTH_KV.
export function consentHelpers(env: Env) {
  return getOAuthApi(oauthOptions, env);
}

// Scopes the consent screen offers: the intersection of what the client asked for and what
// exists. An empty request defaults to least privilege — the human sees exactly what they
// are granting either way.
export function grantableScopes(requested: readonly string[]): M2MScope[] {
  const granted = BROWSER_FLOW_SCOPES.filter((s) => requested.includes(s));
  return granted.length > 0 ? granted : ["agent"];
}

export function effectiveScope(granted: readonly M2MScope[]): M2MScope {
  return granted.includes("admin") ? "admin" : "agent";
}

// --- consent-state blob (CSRF / confused-deputy defense) ---
//
// The consent POST must prove the decision belongs to the auth request the SAME tenant was
// shown: CF Access sessions ride on cookies, so a cross-site form post (or a blob minted
// under the attacker's own Access session) would otherwise decide on the victim's behalf.
// The blob HMAC-binds {tenant, parsed auth request, expiry}; verification additionally
// requires blob.tenant === the CF Access JWT tenant on the POST. Key is HKDF-derived from
// M2M_TOKEN_SIGNING_SECRET with a versioned info string — domain-separated from the JWTs
// that secret signs, no second deploy-day secret to manage.

const CONSENT_STATE_VERSION = "cs1";
const CONSENT_STATE_TTL_SECONDS = 10 * 60;
const CONSENT_DERIVE_INFO = "kajaril-consent-state-v1";
// The auth request echoes attacker-influenced query params (state, scope). Anything bigger
// than this is hostile and refused before crypto or KV work.
const MAX_CONSENT_BLOB_CHARS = 8 * 1024;
export const MAX_AUTH_REQUEST_STATE_CHARS = 2048;

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

async function consentHmacKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
  const master = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(CONSENT_DERIVE_INFO),
    },
    master,
    256,
  );
  return crypto.subtle.importKey("raw", bits, { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

export interface ConsentState {
  tenant: string;
  authRequest: AuthRequest;
}

export async function mintConsentState(
  secret: string,
  state: ConsentState,
  nowMs: number = Date.now(),
): Promise<string> {
  if (!secret) throw new Error("consent state secret is empty");
  if (!isValidClientIdShape(state.tenant)) throw new Error("invalid tenant");
  const body = JSON.stringify({
    t: state.tenant,
    r: state.authRequest,
    e: Math.floor(nowMs / 1000) + CONSENT_STATE_TTL_SECONDS,
  });
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(body));
  const signedPart = `${CONSENT_STATE_VERSION}.${payloadB64}`;
  const key = await consentHmacKey(secret, "sign");
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPart));
  return `${signedPart}.${base64UrlEncode(new Uint8Array(sig))}`;
}

export async function verifyConsentState(
  secret: string,
  blob: string,
  nowMs: number = Date.now(),
): Promise<ConsentState | null> {
  if (!secret || typeof blob !== "string" || blob.length > MAX_CONSENT_BLOB_CHARS) return null;

  const parts = blob.split(".");
  if (parts.length !== 3) return null;
  const [version, payloadB64, sigB64] = parts as [string, string, string];
  if (version !== CONSENT_STATE_VERSION) return null;

  const sigBytes = base64UrlDecode(sigB64);
  const payloadBytes = base64UrlDecode(payloadB64);
  if (!sigBytes || !payloadBytes) return null;

  try {
    const key = await consentHmacKey(secret, "verify");
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

  let parsed: { t?: unknown; r?: unknown; e?: unknown };
  try {
    parsed = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }
  const { t, r, e } = parsed;
  if (typeof t !== "string" || !isValidClientIdShape(t)) return null;
  if (typeof r !== "object" || r === null) return null;
  if (typeof e !== "number" || !Number.isInteger(e)) return null;
  if (e * 1000 < nowMs) return null;

  return { tenant: t, authRequest: r as AuthRequest };
}
