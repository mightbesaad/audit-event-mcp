import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Env } from "@/lib/types";
import { MCP_TOOL_DEFINITIONS } from "@/mcp/tool-definitions";

export { AuditDO } from "@/do";

const app = new Hono<{ Bindings: Env }>();

app.use("*", cors({ origin: "*" }));

// CF Access JWT decode — extracts custom.client_id claim.
// CF Access validates the JWT signature at the network layer before the Worker receives the request.
// Worker-side signature verification against JWKS is deferred to M8-next.
function extractClientId(jwt: string): string | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = (parts[1] ?? "").replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
    const payload = JSON.parse(json) as Record<string, unknown>;
    const custom = payload.custom;
    if (typeof custom !== "object" || custom === null) return null;
    const clientId = (custom as Record<string, unknown>).client_id;
    return typeof clientId === "string" ? clientId : null;
  } catch {
    return null;
  }
}

app.get("/health", (c) => {
  return c.json({ status: "ok", product: "audit-event-mcp", version: "0.1.0" });
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

  const clientId = extractClientId(jwtHeader);
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
      const doRes = await stub.fetch(`https://do-internal${doPath}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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

export default { fetch: app.fetch };
