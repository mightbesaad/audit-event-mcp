import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditDO } from "@/do";
import worker from "@/index";
import { sha256Hex, verifyAccessToken } from "@/lib/m2m";
import type { Env } from "@/lib/types";
import { fakeEnv, makeState, post } from "./harness";

const { DatabaseSync: DBSync } = await import("node:sqlite");

const SIGNING_SECRET = "test-m2m-signing-secret";
const CLIENT_ID = "client-test";

function tokenRequest(
  body: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return new Request("https://audit-event.kajaril.com/oauth/token", {
    method: "POST",
    headers,
    body: new URLSearchParams(body),
  });
}

function basicAuth(clientId: string, clientSecret: string): Record<string, string> {
  return { Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}` };
}

describe("POST /oauth/token", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let idFromName: ReturnType<typeof vi.fn>;
  let env: Env;

  beforeEach(() => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
    idFromName = vi.fn((name: string) => name);
    env = {
      AUDIT_DO: {
        idFromName,
        get: () => ({
          fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
        }),
      } as unknown as Env["AUDIT_DO"],
      M2M_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
    } as Env;
  });

  afterEach(() => {
    db.close();
  });

  async function seedCredential(scope: "agent" | "admin", secret: string): Promise<void> {
    const res = await do_.fetch(post("/credential/set", { scope, secretHash: await sha256Hex(secret) }));
    expect(res.status).toBe(200);
  }

  const GRANT = { grant_type: "client_credentials", scope: "agent" };

  it("issues a verifiable agent token for body-param credentials", async () => {
    await seedCredential("agent", "kjr_agent_correct");
    const res = await worker.fetch(
      tokenRequest({ ...GRANT, client_id: CLIENT_ID, client_secret: "kjr_agent_correct" }),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("agent");
    expect(await verifyAccessToken(SIGNING_SECRET, body.access_token)).toEqual({
      clientId: CLIENT_ID,
      scope: "agent",
    });
  });

  it("accepts HTTP Basic client authentication", async () => {
    await seedCredential("admin", "kjr_admin_correct");
    const res = await worker.fetch(
      tokenRequest(
        { grant_type: "client_credentials", scope: "admin" },
        basicAuth(CLIENT_ID, "kjr_admin_correct"),
      ),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    expect(await verifyAccessToken(SIGNING_SECRET, body.access_token)).toEqual({
      clientId: CLIENT_ID,
      scope: "admin",
    });
  });

  it("rejects a wrong secret with a uniform invalid_client", async () => {
    await seedCredential("agent", "kjr_agent_correct");
    const res = await worker.fetch(
      tokenRequest({ ...GRANT, client_id: CLIENT_ID, client_secret: "kjr_agent_wrong" }),
      env,
      {} as never,
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Basic");
    expect(((await res.json()) as { error: string }).error).toBe("invalid_client");
  });

  it("rejects a client with no issued credential (empty tenant DO)", async () => {
    const res = await worker.fetch(
      tokenRequest({ ...GRANT, client_id: "nobody", client_secret: "kjr_agent_anything" }),
      env,
      {} as never,
    );
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_client");
  });

  it("never lets an agent credential mint an admin token", async () => {
    await seedCredential("agent", "kjr_agent_correct");
    // No admin credential exists — requesting admin scope with the agent secret must fail.
    const res = await worker.fetch(
      tokenRequest({
        grant_type: "client_credentials",
        scope: "admin",
        client_id: CLIENT_ID,
        client_secret: "kjr_agent_correct",
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(401);

    // Even with an admin credential issued, the agent secret must not satisfy admin scope.
    await seedCredential("admin", "kjr_admin_other");
    const res2 = await worker.fetch(
      tokenRequest({
        grant_type: "client_credentials",
        scope: "admin",
        client_id: CLIENT_ID,
        client_secret: "kjr_agent_correct",
      }),
      env,
      {} as never,
    );
    expect(res2.status).toBe(401);
  });

  it("rejects unsupported grant types and missing/unknown scopes", async () => {
    const wrongGrant = await worker.fetch(
      tokenRequest({ grant_type: "authorization_code", scope: "agent" }),
      env,
      {} as never,
    );
    expect(wrongGrant.status).toBe(400);
    expect(((await wrongGrant.json()) as { error: string }).error).toBe("unsupported_grant_type");

    for (const scope of [undefined, "root", "agent admin"]) {
      const res = await worker.fetch(
        tokenRequest({
          grant_type: "client_credentials",
          ...(scope === undefined ? {} : { scope }),
          client_id: CLIENT_ID,
          client_secret: "x",
        }),
        env,
        {} as never,
      );
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe("invalid_scope");
    }
  });

  it("rejects a malformed client_id shape before any DO lookup", async () => {
    const res = await worker.fetch(
      tokenRequest({ ...GRANT, client_id: "../escape", client_secret: "kjr_agent_x" }),
      env,
      {} as never,
    );
    expect(res.status).toBe(401);
    expect(idFromName).not.toHaveBeenCalled();
  });

  it("fails closed (503) when the signing secret is unbound", async () => {
    env.M2M_TOKEN_SIGNING_SECRET = undefined;
    const res = await worker.fetch(
      tokenRequest({ ...GRANT, client_id: CLIENT_ID, client_secret: "kjr_agent_x" }),
      env,
      {} as never,
    );
    expect(res.status).toBe(503);
  });

  it("rate-limits before parsing or DO work", async () => {
    const limit = vi.fn(async () => ({ success: false }));
    env.APPROVAL_RATE_LIMITER = { limit } as unknown as RateLimit;
    const res = await worker.fetch(
      tokenRequest(
        { ...GRANT, client_id: CLIENT_ID, client_secret: "kjr_agent_x" },
        { "CF-Connecting-IP": "203.0.113.9" },
      ),
      env,
      {} as never,
    );
    expect(res.status).toBe(429);
    expect(limit).toHaveBeenCalledWith({ key: "tok-ip:203.0.113.9" });
    expect(idFromName).not.toHaveBeenCalled();
  });
});

describe("POST /credentials/rotate", () => {
  let db: DatabaseSync;
  let do_: AuditDO;
  let env: Env;

  beforeEach(() => {
    db = new DBSync(":memory:");
    do_ = new AuditDO(makeState(db), fakeEnv);
    env = {
      AUDIT_DO: {
        idFromName: (name: string) => name,
        get: () => ({
          fetch: (url: string, init?: RequestInit) => do_.fetch(new Request(url, init)),
        }),
      } as unknown as Env["AUDIT_DO"],
      M2M_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
    } as Env;
  });

  afterEach(() => {
    db.close();
  });

  async function adminToken(): Promise<string> {
    await do_.fetch(
      post("/credential/set", { scope: "admin", secretHash: await sha256Hex("kjr_admin_boot") }),
    );
    const res = await worker.fetch(
      tokenRequest({
        grant_type: "client_credentials",
        scope: "admin",
        client_id: CLIENT_ID,
        client_secret: "kjr_admin_boot",
      }),
      env,
      {} as never,
    );
    return ((await res.json()) as { access_token: string }).access_token;
  }

  function rotateRequest(scope: string, token?: string): Request {
    return new Request("https://audit-event.kajaril.com/credentials/rotate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ scope }),
    });
  }

  it("admin Bearer rotates: new secret works, old one stops working", async () => {
    const token = await adminToken();
    const res = await worker.fetch(rotateRequest("agent", token), env, {} as never);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const { clientSecret } = (await res.json()) as { clientSecret: string };
    expect(clientSecret).toMatch(/^kjr_agent_[A-Za-z0-9_-]{43}$/);

    const mint = (secret: string) =>
      worker.fetch(
        tokenRequest({
          grant_type: "client_credentials",
          scope: "agent",
          client_id: CLIENT_ID,
          client_secret: secret,
        }),
        env,
        {} as never,
      );
    expect((await mint(clientSecret)).status).toBe(200);

    const rotatedAgain = await worker.fetch(rotateRequest("agent", token), env, {} as never);
    const second = (await rotatedAgain.json()) as { clientSecret: string };
    expect((await mint(second.clientSecret)).status).toBe(200);
    expect((await mint(clientSecret)).status).toBe(401);
  });

  it("an agent token cannot rotate credentials", async () => {
    const token = await adminToken();
    const agentRes = await worker.fetch(rotateRequest("agent", token), env, {} as never);
    const { clientSecret } = (await agentRes.json()) as { clientSecret: string };
    const agentTokenRes = await worker.fetch(
      tokenRequest({
        grant_type: "client_credentials",
        scope: "agent",
        client_id: CLIENT_ID,
        client_secret: clientSecret,
      }),
      env,
      {} as never,
    );
    const agentToken = ((await agentTokenRes.json()) as { access_token: string }).access_token;

    const res = await worker.fetch(rotateRequest("admin", agentToken), env, {} as never);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("insufficient_scope");
  });

  it("requires auth and a valid scope", async () => {
    expect((await worker.fetch(rotateRequest("agent"), env, {} as never)).status).toBe(401);
    const token = await adminToken();
    expect((await worker.fetch(rotateRequest("root", token), env, {} as never)).status).toBe(400);
  });
});
