import { describe, expect, it } from "vitest";
import worker from "@/index";
import { mintAccessToken } from "@/lib/m2m";
import { kvEmailForClient } from "@/lib/notify";
import type { Env } from "@/lib/types";
import { makeMockKV } from "./harness";

// Channel-connect endpoints on the gated worker (D4): admin-only writes of routing
// config into CHANNELS_KV. No DO, no chain, no telegram traffic is involved here.

const SIGNING_SECRET = "test-m2m-signing-secret";
const CLIENT_ID = "client-test";
const BOT_USERNAME = "kajaril_witness_bot";

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    AUDIT_DO: {} as Env["AUDIT_DO"],
    M2M_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
    CHANNELS_KV: makeMockKV(),
    TELEGRAM_BOT_USERNAME: BOT_USERNAME,
    ...overrides,
  } as Env;
}

function post(path: string, token: string, body?: unknown): Request {
  return new Request(`https://audit-event.kajaril.com${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

const ctx = {} as ExecutionContext;

describe("POST /channels/telegram/connect", () => {
  it("mints a one-time t.me deep link bound to the authenticated tenant", async () => {
    const env = makeEnv();
    const token = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "admin" });
    const res = await worker.fetch(post("/channels/telegram/connect", token), env, ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { url: string; expiresInSeconds: number };

    const match = new RegExp(`^https://t\\.me/${BOT_USERNAME}\\?start=([A-Za-z0-9_-]{22})$`).exec(
      body.url,
    );
    expect(match).not.toBeNull();
    expect(body.expiresInSeconds).toBe(900);
    // The code resolves to the tenant the ADMIN credential chose — the /start redemption
    // on the public worker never trusts anything the Telegram user typed.
    const kv = env.CHANNELS_KV as NonNullable<Env["CHANNELS_KV"]>;
    expect(await kv.get(`tg:connect:${match?.[1]}`)).toBe(CLIENT_ID);
  });

  it("requires the admin scope", async () => {
    const env = makeEnv();
    const token = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "agent" });
    const res = await worker.fetch(post("/channels/telegram/connect", token), env, ctx);
    expect(res.status).toBe(403);
  });

  it("requires credentials at all", async () => {
    const req = new Request("https://audit-event.kajaril.com/channels/telegram/connect", {
      method: "POST",
    });
    const res = await worker.fetch(req, makeEnv(), ctx);
    expect(res.status).toBe(401);
  });

  it("fails closed when KV or the bot username is missing", async () => {
    const token = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "admin" });
    const noKv = await worker.fetch(
      post("/channels/telegram/connect", token),
      makeEnv({ CHANNELS_KV: undefined }),
      ctx,
    );
    expect(noKv.status).toBe(503);
    const noBot = await worker.fetch(
      post("/channels/telegram/connect", token),
      makeEnv({ TELEGRAM_BOT_USERNAME: undefined }),
      ctx,
    );
    expect(noBot.status).toBe(503);
  });
});

describe("POST /channels/email", () => {
  it("stores the approver address for the authenticated tenant", async () => {
    const env = makeEnv();
    const token = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "admin" });
    const res = await worker.fetch(
      post("/channels/email", token, { address: "founder@example.com" }),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    const kv = env.CHANNELS_KV as NonNullable<Env["CHANNELS_KV"]>;
    expect(await kv.get(kvEmailForClient(CLIENT_ID))).toBe("founder@example.com");
  });

  it("rejects implausible addresses", async () => {
    const env = makeEnv();
    const token = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "admin" });
    for (const address of ["", "no-at-sign", "a@b", "spaces in@example.com", 42]) {
      const res = await worker.fetch(post("/channels/email", token, { address }), env, ctx);
      expect(res.status).toBe(400);
    }
  });

  it("requires the admin scope", async () => {
    const env = makeEnv();
    const token = await mintAccessToken(SIGNING_SECRET, { clientId: CLIENT_ID, scope: "agent" });
    const res = await worker.fetch(
      post("/channels/email", token, { address: "founder@example.com" }),
      env,
      ctx,
    );
    expect(res.status).toBe(403);
  });
});
