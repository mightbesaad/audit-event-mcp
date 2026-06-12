import { Hono } from "hono";
import { cors } from "hono/cors";
import { isValidClientIdShape } from "@/lib/approval";
import { checkApproval, requestApproval, tenantStub } from "@/lib/approval-flow";
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
import { RESERVED_EVENT_TYPE_PREFIX } from "@/lib/schema";
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
// Supports ES256 and RS256.
export async function verifyJwt(jwt: string, teamDomain: string): Promise<string | null> {
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
    if (!env.CF_ACCESS_TEAM_DOMAIN) {
      return {
        ok: false,
        status: 503,
        error: "Server misconfigured",
        detail: "CF_ACCESS_TEAM_DOMAIN is not set; refusing to process unverified tokens",
      };
    }
    const clientId = await verifyJwt(cfJwt, env.CF_ACCESS_TEAM_DOMAIN);
    if (!clientId) {
      return { ok: false, status: 401, error: "Unauthorized", detail: "Invalid CF Access token" };
    }
    return { ok: true, clientId, scope: "admin" };
  }

  const authz = req.header("Authorization");
  if (authz?.startsWith("Bearer ")) {
    if (!env.M2M_TOKEN_SIGNING_SECRET) {
      return {
        ok: false,
        status: 503,
        error: "Server misconfigured",
        detail: "M2M_TOKEN_SIGNING_SECRET is not set; refusing to process unverifiable tokens",
      };
    }
    const claims = await verifyAccessToken(
      env.M2M_TOKEN_SIGNING_SECRET,
      authz.slice("Bearer ".length),
    );
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

// --- OAuth 2.1 client-credentials token endpoint (D2) ---
// Hand-rolled on Web Crypto (Day-0 supply-chain rule: no new dependency for this).
// Error vocabulary is RFC 6749 §5.2; every response is uncacheable per §5.1.
app.post("/oauth/token", async (c) => {
  const oauthError = (status: 400 | 401 | 429 | 503, error: string, description: string) =>
    c.json({ error, error_description: description }, status, {
      "Cache-Control": "no-store",
      ...(status === 401 ? { "WWW-Authenticate": 'Basic realm="oauth/token"' } : {}),
    });

  if (!c.env.M2M_TOKEN_SIGNING_SECRET) {
    return oauthError(
      503,
      "temporarily_unavailable",
      "M2M_TOKEN_SIGNING_SECRET is not set; token issuance is disabled",
    );
  }

  // Per-IP cap before any parsing or DO work — this is the only endpoint where an
  // unauthenticated caller can make the worker do real work.
  if (c.env.APPROVAL_RATE_LIMITER) {
    const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
    const { success } = await c.env.APPROVAL_RATE_LIMITER.limit({ key: `tok-ip:${ip}` });
    if (!success) {
      return oauthError(429, "slow_down", "Too many token requests from this address");
    }
  }

  let form: Record<string, unknown>;
  try {
    form = await c.req.parseBody();
  } catch {
    return oauthError(400, "invalid_request", "Body must be application/x-www-form-urlencoded");
  }

  if (form.grant_type !== "client_credentials") {
    return oauthError(
      400,
      "unsupported_grant_type",
      "grant_type must be client_credentials (application/x-www-form-urlencoded body)",
    );
  }

  const scope = form.scope;
  if (!isM2MScope(scope)) {
    return oauthError(400, "invalid_scope", "scope must be exactly 'agent' or 'admin'");
  }

  // Client auth: HTTP Basic preferred (RFC 6749 §2.3.1), form params as the fallback.
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
    clientId = typeof form.client_id === "string" ? form.client_id : undefined;
    clientSecret = typeof form.client_secret === "string" ? form.client_secret : undefined;
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

  if (c.env.APPROVAL_RATE_LIMITER) {
    const { success } = await c.env.APPROVAL_RATE_LIMITER.limit({ key: `tok:${clientId}` });
    if (!success) {
      return oauthError(429, "slow_down", "Too many token requests for this client");
    }
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
        const reqUrl = new URL(c.req.url);
        doHeaders["X-Client-Id"] = clientId;
        doHeaders["X-Base-Url"] = `${reqUrl.protocol}//${reqUrl.host}`;
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

app.get("/dossier/:clientId/:uuid", async (c) => {
  if (!c.env.AUDIT_PAYLOADS) {
    return c.json({ error: "R2 not configured" }, 503);
  }
  const { clientId, uuid } = c.req.param();
  const key = `dossier/${clientId}/${uuid}.jsonl`;
  const obj = await c.env.AUDIT_PAYLOADS.get(key);
  if (!obj) {
    return c.json({ error: "Not found" }, 404);
  }
  const expiresAt = obj.customMetadata?.expiresAt;
  if (expiresAt && new Date(expiresAt) < new Date()) {
    await c.env.AUDIT_PAYLOADS.delete(key);
    return c.json({ error: "Dossier expired" }, 410);
  }
  return new Response(obj.body, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "Content-Disposition": `attachment; filename="${uuid}.jsonl"`,
    },
  });
});

export default { fetch: app.fetch };
