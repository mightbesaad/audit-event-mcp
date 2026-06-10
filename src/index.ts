import { Hono } from "hono";
import { cors } from "hono/cors";
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

app.get("/health", (c) => {
  return c.json({ status: "ok", product: "audit-event-mcp", version: "0.1.0" });
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
  const jwtHeader = c.req.header("CF-Access-Jwt-Assertion");
  if (!jwtHeader) {
    return c.json({ error: "Unauthorized", detail: "CF Access token required" }, 401);
  }

  // Fail closed: the client_id claim selects the per-tenant Durable Object and R2 prefix, so it
  // MUST come from a signature-verified token. Without CF_ACCESS_TEAM_DOMAIN we cannot fetch the
  // JWKS to verify, and decoding the payload unverified would let anyone forge custom.client_id
  // and impersonate any tenant (e.g. by hitting the *.workers.dev URL, which is not behind the
  // Access policy bound to the custom domain). Refuse rather than trust the upstream proxy.
  if (!c.env.CF_ACCESS_TEAM_DOMAIN) {
    return c.json(
      {
        error: "Server misconfigured",
        detail: "CF_ACCESS_TEAM_DOMAIN is not set; refusing to process unverified tokens",
      },
      503,
    );
  }
  const clientId = await verifyJwt(jwtHeader, c.env.CF_ACCESS_TEAM_DOMAIN);
  if (!clientId) {
    return c.json({ error: "Unauthorized", detail: "Invalid CF Access token" }, 401);
  }

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

    const doId = c.env.AUDIT_DO.idFromName(`audit-do-${clientId}`);
    const stub = c.env.AUDIT_DO.get(doId);

    let doPath: string;
    if (toolName === "record_event") doPath = "/record";
    else if (toolName === "verify_chain") doPath = "/verify";
    else if (toolName === "query_events") doPath = "/query";
    else if (toolName === "export_dossier") doPath = "/dossier";
    else {
      return c.json(
        {
          jsonrpc: "2.0",
          id: body.id,
          error: { code: -32601, message: `Unknown tool: ${toolName}` },
        },
        404,
      );
    }

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
