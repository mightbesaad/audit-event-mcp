import { Hono } from "hono";
import { cors } from "hono/cors";
import { isValidClientIdShape } from "@/lib/approval";
import { checkApproval, publicLinkBase, requestApproval, tenantStub } from "@/lib/approval-flow";
import {
  consentSecurityHeaders,
  renderConsentErrorPage,
  renderConsentPage,
} from "@/lib/consent-page";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  constantTimeEqualHex,
  generateClientSecret,
  isM2MScope,
  type M2MScope,
  MAX_CLIENT_SECRET_CHARS,
  mintAccessToken,
  sha256Hex,
  verifyAccessToken,
} from "@/lib/m2m";
import { isValidEmailShape, kvEmailForClient } from "@/lib/notify";
import {
  consentHelpers,
  effectiveScope,
  forwardToOAuthProvider,
  grantableScopes,
  MAX_AUTH_REQUEST_STATE_CHARS,
  mintConsentState,
  unwrapBrowserToken,
  verifyConsentState,
} from "@/lib/oauth-browser";
import { RESERVED_EVENT_TYPE_PREFIX } from "@/lib/schema";
import { CONNECT_CODE_TTL_SECONDS, generateConnectCode, kvConnectCode } from "@/lib/telegram";
import type { Env } from "@/lib/types";
import { MCP_TOOL_DEFINITIONS } from "@/mcp/tool-definitions";

export { AuditDO } from "@/do";

const app = new Hono<{ Bindings: Env }>();

app.use("*", cors({ origin: "*" }));

// --- JWKS-verified JWT extraction ---

type CfJwk = JsonWebKey & { kid: string };

const JWKS_TTL_MS = 5 * 60 * 1000;
const jwksByDomain = new Map<string, { keys: CfJwk[]; fetchedAt: number }>();

function base64UrlDecode(s: string): Uint8Array {
  const padded = s
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(s.length / 4) * 4, "=");
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

async function fetchJwks(teamDomain: string): Promise<CfJwk[]> {
  const cached = jwksByDomain.get(teamDomain);
  if (cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const data = (await res.json()) as { keys: CfJwk[] };
  jwksByDomain.set(teamDomain, { keys: data.keys, fetchedAt: Date.now() });
  return data.keys;
}

// Verifies a CF Access JWT against the team's published JWKS and returns the
// custom.client_id claim, or null if verification fails for any reason.
// Supports ES256 and RS256. The aud claim must name OUR Access application
// (expectedAud): every app on the team domain shares the same signing keys, so
// without the pin a token issued for some other app would verify here too.
export async function verifyJwt(
  jwt: string,
  teamDomain: string,
  expectedAud: string,
): Promise<string | null> {
  if (!expectedAud) return null;
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: { alg?: string; kid?: string };
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
  } catch {
    return null;
  }

  const { alg, kid } = header;
  if (!alg || !kid) return null;

  if (typeof payload.exp === "number" && payload.exp < Date.now() / 1000) return null;

  // CF Access encodes aud as an array of application AUD tags; tolerate a bare string.
  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(expectedAud) : aud === expectedAud;
  if (!audOk) return null;

  try {
    const keys = await fetchJwks(teamDomain);
    const jwk = keys.find((k) => k.kid === kid);
    if (!jwk) return null;

    if (alg !== "ES256" && alg !== "RS256") return null;

    const cryptoKey =
      alg === "ES256"
        ? await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
            "verify",
          ])
        : await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
            false,
            ["verify"],
          );

    const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = base64UrlDecode(sigB64);

    const valid =
      alg === "ES256"
        ? await crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            cryptoKey,
            signature,
            message,
          )
        : await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, cryptoKey, signature, message);
    if (!valid) return null;
  } catch {
    return null;
  }

  const custom = payload.custom;
  if (typeof custom !== "object" || custom === null) return null;
  const clientId = (custom as Record<string, unknown>).client_id;
  return typeof clientId === "string" ? clientId : null;
}

// --- caller authentication (decision D2) ---
// Two ways in, checked in this order:
//   1. CF Access JWT (CF-Access-Jwt-Assertion) — the manually-onboarded service-token path.
//      Admin-equivalent: Access is the outer fence for these tenants. Checked first because
//      Access injects this header on the custom domain regardless of other headers.
//   2. Bearer access token minted by POST /oauth/token — the self-serve M2M path, carrying
//      an agent or admin scope.
// Fail closed in both lanes: the verified claim is the ONLY thing that ever selects a
// tenant DO / R2 prefix, so a missing verification key means refusing the request (503),
// never trusting an undecoded token — anyone could forge client_id on the workers.dev URL.

type AuthOk = { ok: true; clientId: string; scope: M2MScope };
type AuthFail = { ok: false; status: 401 | 503; error: string; detail: string };

async function authenticate(
  req: { header: (name: string) => string | undefined },
  env: Env,
): Promise<AuthOk | AuthFail> {
  const cfJwt = req.header("CF-Access-Jwt-Assertion");
  if (cfJwt) {
    if (!env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_APP_AUD) {
      return {
        ok: false,
        status: 503,
        error: "Server misconfigured",
        detail:
          "CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_APP_AUD must both be set; refusing to process unverified tokens",
      };
    }
    const clientId = await verifyJwt(cfJwt, env.CF_ACCESS_TEAM_DOMAIN, env.CF_ACCESS_APP_AUD);
    if (!clientId) {
      return { ok: false, status: 401, error: "Unauthorized", detail: "Invalid CF Access token" };
    }
    return { ok: true, clientId, scope: "admin" };
  }

  const authz = req.header("Authorization");
  if (authz?.startsWith("Bearer ")) {
    const token = authz.slice("Bearer ".length);

    // Browser-flow opaque tokens (D11) contain ":" (userId:grantId:secret); our M2M JWTs
    // are dot-separated base64url and never can. The shapes are disjoint, so the lane is
    // picked structurally — garbage tokens fail uniformly in either lane.
    if (token.includes(":")) {
      if (!env.OAUTH_KV) {
        return {
          ok: false,
          status: 503,
          error: "Server misconfigured",
          detail: "OAUTH_KV is not bound; refusing to process unverifiable tokens",
        };
      }
      const browserAuth = await unwrapBrowserToken(env, token);
      if (!browserAuth) {
        return {
          ok: false,
          status: 401,
          error: "Unauthorized",
          detail: "Invalid or expired access token",
        };
      }
      return { ok: true, clientId: browserAuth.clientId, scope: browserAuth.scope };
    }

    if (!env.M2M_TOKEN_SIGNING_SECRET) {
      return {
        ok: false,
        status: 503,
        error: "Server misconfigured",
        detail: "M2M_TOKEN_SIGNING_SECRET is not set; refusing to process unverifiable tokens",
      };
    }
    const claims = await verifyAccessToken(env.M2M_TOKEN_SIGNING_SECRET, token);
    if (!claims) {
      return {
        ok: false,
        status: 401,
        error: "Unauthorized",
        detail: "Invalid or expired access token",
      };
    }
    return { ok: true, clientId: claims.clientId, scope: claims.scope };
  }

  return {
    ok: false,
    status: 401,
    error: "Unauthorized",
    detail: "Credentials required: CF Access JWT or Bearer access token",
  };
}

// What an agent-scoped token may call (D2): write evidence, drive approvals. Reading
// chains, querying events, and exporting dossiers stay admin-only.
const AGENT_SCOPE_TOOLS = new Set(["record_event", "request_approval", "check_approval"]);

const DO_PATH_BY_TOOL: Record<string, string> = {
  record_event: "/record",
  verify_chain: "/verify",
  query_events: "/query",
  export_dossier: "/dossier",
};

app.get("/health", (c) => {
  return c.json({ status: "ok", product: "audit-event-mcp", version: "0.1.0" });
});

// --- /oauth/token: one endpoint, routed by grant_type (D11) ---
// The shim owns the route. client_credentials stays on the hand-rolled D10 path below;
// authorization_code / refresh_token (and the RFC 7009 revocation shape the metadata
// advertises at this endpoint) forward to workers-oauth-provider. All six D11 conditions
// are load-bearing here:
//   1. per-IP and per-client caps fire BEFORE the branch — the library path is equally capped
//   2. uniform RFC 6749 vocabulary from every branch; missing/unknown grant_type is
//      unsupported_grant_type, never a 404, and no response shape reveals which path exists
//   3. the body is buffered exactly once, reconstructed for the library, and never logged
//      (client secrets travel in form bodies)
//   4. RFC 8414 metadata (below) advertises this single endpoint
//   5. the library-owned surfaces get the adversarial tests in test/oauth-browser.test.ts
//   6. OAUTH_KV is a deploy-day create-and-bind (wrangler.jsonc)

// Form bodies here are credentials + grant parameters — generous cap, but bounded before
// any crypto, KV, or DO work happens on hostile input.
const MAX_TOKEN_BODY_CHARS = 16 * 1024;

app.post("/oauth/token", async (c) => {
  const oauthError = (status: 400 | 401 | 429 | 503, error: string, description: string) =>
    c.json({ error, error_description: description }, status, {
      "Cache-Control": "no-store",
      ...(status === 401 ? { "WWW-Authenticate": 'Basic realm="oauth/token"' } : {}),
    });

  // Per-IP cap before any parsing — an unauthenticated caller can make every branch of
  // this endpoint do real work.
  if (c.env.APPROVAL_RATE_LIMITER) {
    const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
    const { success } = await c.env.APPROVAL_RATE_LIMITER.limit({ key: `tok-ip:${ip}` });
    if (!success) {
      return oauthError(429, "slow_down", "Too many token requests from this address");
    }
  }

  const contentType = c.req.header("Content-Type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return oauthError(400, "invalid_request", "Body must be application/x-www-form-urlencoded");
  }

  // The one and only body read (D11 condition 3).
  let rawBody: string;
  try {
    rawBody = await c.req.text();
  } catch {
    return oauthError(400, "invalid_request", "Body could not be read");
  }
  if (rawBody.length > MAX_TOKEN_BODY_CHARS) {
    return oauthError(400, "invalid_request", "Body too large");
  }
  const form = new URLSearchParams(rawBody);
  const grantType = form.get("grant_type");

  // Client auth: HTTP Basic preferred (RFC 6749 §2.3.1), form params as the fallback.
  // Extracted once, before the branch — the per-client cap needs the identifier, and a
  // malformed Basic header is refused uniformly so no branch can be probed with one.
  let clientId: string | undefined;
  let clientSecret: string | undefined;
  const authz = c.req.header("Authorization");
  if (authz?.startsWith("Basic ")) {
    try {
      const decoded = atob(authz.slice("Basic ".length));
      const sep = decoded.indexOf(":");
      if (sep === -1) throw new Error("no separator");
      clientId = decodeURIComponent(decoded.slice(0, sep));
      clientSecret = decodeURIComponent(decoded.slice(sep + 1));
    } catch {
      return oauthError(401, "invalid_client", "Malformed Basic authorization header");
    }
  } else {
    clientId = form.get("client_id") ?? undefined;
    clientSecret = form.get("client_secret") ?? undefined;
  }

  // Per-client cap before the branch (D11 condition 1). The identifier is only a rate key
  // at this point — validation happens inside each branch. Bounded so a hostile id cannot
  // bloat the rate-limiter key space per request.
  if (clientId && c.env.APPROVAL_RATE_LIMITER) {
    const { success } = await c.env.APPROVAL_RATE_LIMITER.limit({
      key: `tok:${clientId.slice(0, 256)}`,
    });
    if (!success) {
      return oauthError(429, "slow_down", "Too many token requests for this client");
    }
  }

  // --- branch: library-owned grants (D11) ---
  const isRevocationShape = grantType === null && form.get("token") !== null;
  if (grantType === "authorization_code" || grantType === "refresh_token" || isRevocationShape) {
    if (!c.env.OAUTH_KV) {
      return oauthError(
        503,
        "temporarily_unavailable",
        "OAUTH_KV is not bound; this grant type is disabled",
      );
    }
    // Reconstruct the request from the single buffered body (condition 3). The library
    // speaks the same RFC 6749 vocabulary, so responses stay uniform across branches.
    const reconstructed = new Request(c.req.raw.url, {
      method: "POST",
      headers: c.req.raw.headers,
      body: rawBody,
    });
    const res = await forwardToOAuthProvider(reconstructed, c.env, c.executionCtx);
    if (res.headers.has("Cache-Control")) return res;
    const withNoStore = new Response(res.body, res);
    withNoStore.headers.set("Cache-Control", "no-store");
    return withNoStore;
  }

  // --- branch: hand-rolled client_credentials (D10) ---
  if (grantType !== "client_credentials") {
    return oauthError(
      400,
      "unsupported_grant_type",
      "grant_type must be client_credentials, authorization_code, or refresh_token",
    );
  }

  if (!c.env.M2M_TOKEN_SIGNING_SECRET) {
    return oauthError(
      503,
      "temporarily_unavailable",
      "M2M_TOKEN_SIGNING_SECRET is not set; token issuance is disabled",
    );
  }

  const scope = form.get("scope");
  if (!isM2MScope(scope)) {
    return oauthError(400, "invalid_scope", "scope must be exactly 'agent' or 'admin'");
  }

  // Uniform invalid_client for every credential failure from here on — malformed id,
  // unknown tenant, no credential issued, wrong secret — so the endpoint confirms
  // nothing about which tenants exist.
  if (
    !clientId ||
    !clientSecret ||
    !isValidClientIdShape(clientId) ||
    clientSecret.length > MAX_CLIENT_SECRET_CHARS
  ) {
    return oauthError(401, "invalid_client", "Client authentication failed");
  }

  // The one place an unverified client_id reaches idFromName: a credential cannot be
  // checked without reading the claimed tenant's stored hash. Shape-checked and
  // rate-limited above, and nothing leaves this handler unless the presented secret
  // hashes to that stored value — an empty DO for a made-up tenant holds no credential
  // row, so the comparison can never succeed.
  const credRes = await tenantStub(c.env, clientId).fetch("https://do-internal/credential/get", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope }),
  });
  if (!credRes.ok) {
    return oauthError(401, "invalid_client", "Client authentication failed");
  }
  const { secretHash } = (await credRes.json()) as { secretHash: string };

  if (!constantTimeEqualHex(await sha256Hex(clientSecret), secretHash)) {
    return oauthError(401, "invalid_client", "Client authentication failed");
  }

  const accessToken = await mintAccessToken(c.env.M2M_TOKEN_SIGNING_SECRET, { clientId, scope });
  return c.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope,
    },
    200,
    { "Cache-Control": "no-store", Pragma: "no-cache" },
  );
});

// --- library-owned browser-flow surfaces (D11): DCR, metadata, consent ---

// Dynamic client registration. Unauthenticated by design (RFC 7591) — hostile registrants
// are the norm (D11 condition 5), so it is IP-capped like the token endpoint and size-capped
// by the library (1 MiB). Everything it writes is OAUTH_KV config, never evidence.
app.post("/oauth/register", async (c) => {
  const oauthError = (status: 429 | 503, error: string, description: string) =>
    c.json({ error, error_description: description }, status, { "Cache-Control": "no-store" });

  if (c.env.APPROVAL_RATE_LIMITER) {
    const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
    const { success } = await c.env.APPROVAL_RATE_LIMITER.limit({ key: `reg-ip:${ip}` });
    if (!success) {
      return oauthError(429, "slow_down", "Too many registration requests from this address");
    }
  }
  if (!c.env.OAUTH_KV) {
    return oauthError(
      503,
      "temporarily_unavailable",
      "OAUTH_KV is not bound; client registration is disabled",
    );
  }
  return forwardToOAuthProvider(c.req.raw, c.env, c.executionCtx);
});

// RFC 8414 metadata, generated by the library and augmented at the shim: the library only
// knows its own grants, but the single advertised /oauth/token (D11 condition 4) also
// accepts client_credentials on the hand-rolled path.
app.get("/.well-known/oauth-authorization-server", async (c) => {
  const res = await forwardToOAuthProvider(c.req.raw, c.env, c.executionCtx);
  if (!res.ok) return res;
  const metadata = (await res.json()) as Record<string, unknown>;
  const grants = Array.isArray(metadata.grant_types_supported)
    ? (metadata.grant_types_supported as string[])
    : [];
  metadata.grant_types_supported = [...grants, "client_credentials"];
  return c.json(metadata);
});

// RFC 9728 protected-resource metadata — how MCP clients discover the authorization server.
app.get("/.well-known/oauth-protected-resource", (c) =>
  forwardToOAuthProvider(c.req.raw, c.env, c.executionCtx),
);
app.get("/.well-known/oauth-protected-resource/*", (c) =>
  forwardToOAuthProvider(c.req.raw, c.env, c.executionCtx),
);

// --- consent (D11): rendered by us, completed through the library's helpers ---
// The human consenting is a tenant operator authenticated by the CF Access SSO session on
// this domain — the only human-login fence the gated worker has. Bearer tokens cannot
// consent: a stolen agent credential must never be able to mint itself a browser grant.
// userId / props.clientId are set from the verified Access JWT, so nothing the OAuth
// client supplied ever selects a tenant (the D1/D3 law, third lane).

type ConsentReady = { ok: true; tenant: string };
type ConsentBlocked = { ok: false; response: Response | Promise<Response> };

async function consentGate(c: {
  req: { header: (name: string) => string | undefined };
  env: Env;
  html: (html: string, status: 401 | 503) => Response | Promise<Response>;
}): Promise<ConsentReady | ConsentBlocked> {
  if (
    !c.env.OAUTH_KV ||
    !c.env.M2M_TOKEN_SIGNING_SECRET ||
    !c.env.CF_ACCESS_TEAM_DOMAIN ||
    !c.env.CF_ACCESS_APP_AUD
  ) {
    return {
      ok: false,
      response: c.html(
        renderConsentErrorPage(
          "Unavailable",
          "The authorization service is not fully configured. Try again later.",
        ),
        503,
      ),
    };
  }
  const cfJwt = c.req.header("CF-Access-Jwt-Assertion");
  const tenant = cfJwt
    ? await verifyJwt(cfJwt, c.env.CF_ACCESS_TEAM_DOMAIN, c.env.CF_ACCESS_APP_AUD)
    : null;
  if (!tenant || !isValidClientIdShape(tenant)) {
    return {
      ok: false,
      response: c.html(
        renderConsentErrorPage(
          "Sign-in required",
          "Authorizing an application requires a signed-in operator session (Cloudflare Access). Open this page through your access link.",
        ),
        401,
      ),
    };
  }
  return { ok: true, tenant };
}

app.get("/oauth/authorize", async (c) => {
  consentSecurityHeaders(c);

  if (c.env.APPROVAL_RATE_LIMITER) {
    const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
    const { success } = await c.env.APPROVAL_RATE_LIMITER.limit({ key: `auth-ip:${ip}` });
    if (!success) {
      return c.html(
        renderConsentErrorPage("Slow down", "Too many authorization requests. Try again shortly."),
        429,
      );
    }
  }

  const gate = await consentGate(c);
  if (!gate.ok) return gate.response;

  // state echoes back to the client verbatim and rides inside our signed consent blob —
  // bound before any parsing so a hostile value cannot bloat either.
  if ((c.req.query("state") ?? "").length > MAX_AUTH_REQUEST_STATE_CHARS) {
    return c.html(renderConsentErrorPage("Invalid request", "state parameter too long"), 400);
  }

  const helpers = consentHelpers(c.env);
  let authReq: Awaited<ReturnType<typeof helpers.parseAuthRequest>>;
  try {
    authReq = await helpers.parseAuthRequest(c.req.raw);
  } catch (e) {
    // Library validation messages are fixed strings (never echo request content), and the
    // page must NEVER redirect on a failed parse — an unvalidated redirect_uri is exactly
    // what an open redirect is made of.
    const msg = e instanceof Error ? e.message : "Invalid authorization request";
    return c.html(renderConsentErrorPage("Invalid request", msg), 400);
  }

  if (!authReq.clientId || !authReq.redirectUri || authReq.responseType !== "code") {
    return c.html(
      renderConsentErrorPage(
        "Invalid request",
        "response_type=code with client_id and redirect_uri is required",
      ),
      400,
    );
  }

  const client = await helpers.lookupClient(authReq.clientId);
  if (!client) {
    return c.html(renderConsentErrorPage("Invalid request", "Unknown client"), 400);
  }

  // OAuth 2.1: public clients get no secret, so the code is only bound to its requester
  // via PKCE — without a challenge, a leaked redirect is a token.
  if (client.tokenEndpointAuthMethod === "none" && !authReq.codeChallenge) {
    return c.html(
      renderConsentErrorPage("Invalid request", "PKCE (S256 code_challenge) is required"),
      400,
    );
  }

  const stateBlob = await mintConsentState(c.env.M2M_TOKEN_SIGNING_SECRET as string, {
    tenant: gate.tenant,
    authRequest: authReq,
  });

  return c.html(
    renderConsentPage({
      client,
      tenant: gate.tenant,
      scopes: grantableScopes(authReq.scope),
      redirectUri: authReq.redirectUri,
      stateBlob,
    }),
  );
});

app.post("/oauth/authorize/decision", async (c) => {
  consentSecurityHeaders(c);

  const gate = await consentGate(c);
  if (!gate.ok) return gate.response;

  let blob: string | undefined;
  let decision: string | undefined;
  try {
    const form = await c.req.formData();
    const rawBlob = form.get("consent_state");
    const rawDecision = form.get("decision");
    blob = typeof rawBlob === "string" ? rawBlob : undefined;
    decision = typeof rawDecision === "string" ? rawDecision : undefined;
  } catch {
    return c.html(renderConsentErrorPage("Invalid request", "Malformed form body"), 400);
  }

  const state = blob
    ? await verifyConsentState(c.env.M2M_TOKEN_SIGNING_SECRET as string, blob)
    : null;
  if (!state) {
    return c.html(
      renderConsentErrorPage(
        "Request expired",
        "This authorization request is invalid or has expired. Start again from your application.",
      ),
      400,
    );
  }
  // The blob was minted for the tenant who was SHOWN the consent screen. A blob from any
  // other Access session deciding here would be a confused deputy — refuse.
  if (state.tenant !== gate.tenant) {
    return c.html(
      renderConsentErrorPage(
        "Session mismatch",
        "This authorization request belongs to a different operator session.",
      ),
      403,
    );
  }

  const authReq = state.authRequest;
  const helpers = consentHelpers(c.env);
  const client = await helpers.lookupClient(authReq.clientId);
  // Exact-match redirect validation before ANY redirect leaves this handler — including
  // the deny path, which builds its redirect by hand.
  if (!client?.redirectUris.includes(authReq.redirectUri)) {
    return c.html(renderConsentErrorPage("Invalid request", "Unknown client or redirect"), 400);
  }

  if (decision === "deny") {
    const url = new URL(authReq.redirectUri);
    url.searchParams.set("error", "access_denied");
    if (authReq.state) url.searchParams.set("state", authReq.state);
    return c.redirect(url.toString(), 302);
  }
  if (decision !== "approve") {
    return c.html(renderConsentErrorPage("Invalid request", "Unknown decision"), 400);
  }

  const granted = grantableScopes(authReq.scope);
  try {
    const { redirectTo } = await helpers.completeAuthorization({
      request: authReq,
      userId: gate.tenant,
      metadata: { consentedAt: new Date().toISOString() },
      scope: granted,
      props: { clientId: gate.tenant, scope: effectiveScope(granted) },
    });
    return c.redirect(redirectTo, 302);
  } catch {
    return c.html(
      renderConsentErrorPage("Authorization failed", "Could not complete the authorization."),
      400,
    );
  }
});

// Mint or rotate an M2M client secret (D2): one credential per scope, issued separately,
// rotated independently. The founder's CF Access service token bootstraps the first
// credential during onboarding; an admin Bearer token can rotate from then on. The
// plaintext secret appears exactly once, in this response — only its hash is stored.
app.post("/credentials/rotate", async (c) => {
  const auth = await authenticate(c.req, c.env);
  if (!auth.ok) return c.json({ error: auth.error, detail: auth.detail }, auth.status);
  if (auth.scope !== "admin") {
    return c.json(
      { error: "insufficient_scope", detail: "Rotating credentials requires the admin scope" },
      403,
    );
  }

  let scope: unknown;
  try {
    scope = ((await c.req.json()) as { scope?: unknown }).scope;
  } catch {
    return c.json({ error: "invalid_json" }, 400);
  }
  if (!isM2MScope(scope)) {
    return c.json(
      { error: "invalid_scope", detail: "scope must be exactly 'agent' or 'admin'" },
      400,
    );
  }

  const clientSecret = generateClientSecret(scope);
  const res = await tenantStub(c.env, auth.clientId).fetch("https://do-internal/credential/set", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope, secretHash: await sha256Hex(clientSecret) }),
  });
  if (!res.ok) return c.json({ error: "credential_store_failed" }, 500);

  return c.json(
    {
      clientId: auth.clientId,
      scope,
      clientSecret,
      note: "Store this now — it is shown once and never retrievable. Rotating replaces it immediately.",
    },
    200,
    { "Cache-Control": "no-store" },
  );
});

// --- channel connect (D4) ---
// Channel config is admin surface: an agent-scoped credential must not be able to point
// approval traffic at an attacker's chat or inbox. Both endpoints write routing state to
// CHANNELS_KV only — never the chain, never the DO.

// Mints the one-time Telegram deep link. The tenant is auth.clientId — chosen by the
// admin credential, so the /start redemption on the public worker never picks a tenant
// from anything the Telegram user typed.
app.post("/channels/telegram/connect", async (c) => {
  const auth = await authenticate(c.req, c.env);
  if (!auth.ok) return c.json({ error: auth.error, detail: auth.detail }, auth.status);
  if (auth.scope !== "admin") {
    return c.json(
      { error: "insufficient_scope", detail: "Connecting channels requires the admin scope" },
      403,
    );
  }
  if (!c.env.CHANNELS_KV || !c.env.TELEGRAM_BOT_USERNAME) {
    return c.json(
      {
        error: "channel_unconfigured",
        detail: "CHANNELS_KV and TELEGRAM_BOT_USERNAME must be bound to connect Telegram",
      },
      503,
    );
  }

  const code = generateConnectCode();
  await c.env.CHANNELS_KV.put(kvConnectCode(code), auth.clientId, {
    expirationTtl: CONNECT_CODE_TTL_SECONDS,
  });
  return c.json(
    {
      url: `https://t.me/${c.env.TELEGRAM_BOT_USERNAME}?start=${code}`,
      expiresInSeconds: CONNECT_CODE_TTL_SECONDS,
      note: "Open in Telegram and press Start. One-time use; connecting again replaces the bound chat.",
    },
    200,
    { "Cache-Control": "no-store" },
  );
});

// Sets the approver address for the email fallback channel. Overwrite-only in v1;
// removal joins the admin surface (v1.5).
app.post("/channels/email", async (c) => {
  const auth = await authenticate(c.req, c.env);
  if (!auth.ok) return c.json({ error: auth.error, detail: auth.detail }, auth.status);
  if (auth.scope !== "admin") {
    return c.json(
      { error: "insufficient_scope", detail: "Connecting channels requires the admin scope" },
      403,
    );
  }
  if (!c.env.CHANNELS_KV) {
    return c.json(
      { error: "channel_unconfigured", detail: "CHANNELS_KV must be bound to configure email" },
      503,
    );
  }

  let address: unknown;
  try {
    address = ((await c.req.json()) as { address?: unknown }).address;
  } catch {
    return c.json({ error: "invalid_json" }, 400);
  }
  if (typeof address !== "string" || !isValidEmailShape(address)) {
    return c.json(
      { error: "invalid_address", detail: "address must be a plausible email address" },
      400,
    );
  }

  await c.env.CHANNELS_KV.put(kvEmailForClient(auth.clientId), address);
  return c.json({ clientId: auth.clientId, address }, 200, { "Cache-Control": "no-store" });
});

// --- REST approval surface (D2: the production lane for M2M clients) ---
// Same flow functions as the MCP tools; {status, body} passes through unchanged.

app.post("/approvals", async (c) => {
  const auth = await authenticate(c.req, c.env);
  if (!auth.ok) return c.json({ error: auth.error, detail: auth.detail }, auth.status);

  let input: unknown;
  try {
    input = await c.req.json();
  } catch {
    return c.json({ error: "invalid_json" }, 400);
  }
  const flow = await requestApproval(c.env, auth.clientId, input);
  return c.json(flow.body as Record<string, unknown>, flow.status as 200);
});

app.get("/approvals/:id", async (c) => {
  const auth = await authenticate(c.req, c.env);
  if (!auth.ok) return c.json({ error: auth.error, detail: auth.detail }, auth.status);

  const flow = await checkApproval(c.env, auth.clientId, c.req.param("id"));
  return c.json(flow.body as Record<string, unknown>, flow.status as 200);
});

app.get("/.well-known/mcp/server-card.json", (c) => {
  return c.json({
    serverInfo: { name: "audit-event-mcp", version: "0.1.0" },
    tools: MCP_TOOL_DEFINITIONS,
    resources: [],
    prompts: [],
  });
});

app.get("/mcp", (c) => {
  return c.json(
    {
      error: "Method Not Allowed",
      detail: "The MCP endpoint accepts POST requests only. See https://kajaril.com/audit-event/",
    },
    405,
  );
});

app.post("/mcp", async (c) => {
  const auth = await authenticate(c.req, c.env);
  if (!auth.ok) {
    return c.json({ error: auth.error, detail: auth.detail }, auth.status);
  }
  const clientId = auth.clientId;

  let body: { jsonrpc: string; id?: unknown; method?: string; params?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } },
      400,
    );
  }

  if (body.jsonrpc !== "2.0") {
    return c.json(
      { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32600, message: "Invalid Request" } },
      400,
    );
  }

  if (body.method === "initialize") {
    return c.json({
      jsonrpc: "2.0",
      id: body.id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "audit-event-mcp", version: "0.1.0" },
        capabilities: { tools: {} },
      },
    });
  }

  if (body.method === "notifications/initialized") {
    return c.json({}, 200);
  }

  if (body.method === "tools/list") {
    return c.json({
      jsonrpc: "2.0",
      id: body.id,
      result: { tools: MCP_TOOL_DEFINITIONS },
    });
  }

  if (body.method === "tools/call") {
    const params = body.params as
      | { name?: string; arguments?: Record<string, unknown> }
      | undefined;
    const toolName = params?.name;
    const toolArgs = params?.arguments ?? {};

    if (typeof toolName !== "string") {
      return c.json(
        {
          jsonrpc: "2.0",
          id: body.id ?? null,
          error: { code: -32600, message: "tools/call requires params.name" },
        },
        400,
      );
    }

    const isApprovalFlowTool = toolName === "request_approval" || toolName === "check_approval";
    const doPath = DO_PATH_BY_TOOL[toolName];
    if (!isApprovalFlowTool && doPath === undefined) {
      return c.json(
        {
          jsonrpc: "2.0",
          id: body.id,
          error: { code: -32601, message: `Unknown tool: ${toolName}` },
        },
        404,
      );
    }

    // Scope gate (D2). CF Access callers arrive as admin; agent-scoped Bearer tokens may
    // write evidence and drive approvals but never read chains or export dossiers.
    if (auth.scope !== "admin" && !AGENT_SCOPE_TOOLS.has(toolName)) {
      return c.json(
        {
          jsonrpc: "2.0",
          id: body.id,
          error: {
            code: -32001,
            message: `insufficient scope: ${toolName} requires the admin scope`,
          },
        },
        403,
      );
    }

    // approval.* chain events are emitted by the witness itself when an approval is
    // requested/decided. An agent recording one directly would fabricate human-decision
    // evidence, so the public surface refuses them (D7).
    if (toolName === "record_event") {
      const eventType = (toolArgs as { eventType?: unknown }).eventType;
      if (typeof eventType === "string" && eventType.startsWith(RESERVED_EVENT_TYPE_PREFIX)) {
        return c.json(
          {
            jsonrpc: "2.0",
            id: body.id,
            error: {
              code: -32602,
              message: `${RESERVED_EVENT_TYPE_PREFIX}* event types are reserved — the witness records them when approvals are requested and decided`,
            },
          },
          400,
        );
      }
    }

    // The two approval tools go through the worker-layer flow (rate limit, chain event,
    // approval_url/webhookSecret minting), not straight to a DO path. The JWT-verified
    // clientId is the only tenant selector either flow ever sees.
    if (toolName === "request_approval") {
      const flow = await requestApproval(c.env, clientId, toolArgs);
      return c.json({ jsonrpc: "2.0", id: body.id, result: flow.body }, flow.status as 200);
    }
    if (toolName === "check_approval") {
      const approvalId = (toolArgs as { approvalId?: unknown }).approvalId;
      if (typeof approvalId !== "string") {
        return c.json(
          {
            jsonrpc: "2.0",
            id: body.id,
            error: { code: -32602, message: "check_approval requires arguments.approvalId" },
          },
          400,
        );
      }
      const flow = await checkApproval(c.env, clientId, approvalId);
      return c.json({ jsonrpc: "2.0", id: body.id, result: flow.body }, flow.status as 200);
    }

    const doId = c.env.AUDIT_DO.idFromName(`audit-do-${clientId}`);
    const stub = c.env.AUDIT_DO.get(doId);

    try {
      const doHeaders: Record<string, string> = { "Content-Type": "application/json" };
      if (doPath === "/dossier") {
        doHeaders["X-Client-Id"] = clientId;
        // Dossier links point at the public go worker (D1, Day 5): downloads moved off
        // this gated worker, which closed its one pre-existing public path.
        doHeaders["X-Base-Url"] = publicLinkBase(c.env);
      }
      const doRes = await stub.fetch(`https://do-internal${doPath}`, {
        method: "POST",
        headers: doHeaders,
        body: JSON.stringify(toolArgs),
      });
      const result = await doRes.json();
      if (!doRes.ok) {
        return c.json({ jsonrpc: "2.0", id: body.id, result }, doRes.status as 400 | 500);
      }
      return c.json({ jsonrpc: "2.0", id: body.id, result });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unhandled error";
      return c.json({ jsonrpc: "2.0", id: body.id, result: { error: msg } }, 500);
    }
  }

  return c.json(
    {
      jsonrpc: "2.0",
      id: body.id ?? null,
      error: { code: -32601, message: `Method not found: ${body.method}` },
    },
    404,
  );
});

// The public GET /dossier/:clientId/:uuid route that lived here until Day 5 was the one
// pre-existing hole in the everything-authenticated invariant. It now lives on the go
// worker (D1), reached through the DossierInternal entrypoint in src/main.ts — this
// worker's public route table no longer serves anything unauthenticated but the OAuth
// endpoints, which ARE the gate.

export default { fetch: app.fetch };
