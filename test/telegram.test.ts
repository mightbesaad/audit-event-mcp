import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "@/go";
import type { ApprovalRecord, DecideResult } from "@/lib/approval";
import {
  botIdFromToken,
  buildApprovalCard,
  buildReasonPrompt,
  constantTimeEqualString,
  generateConnectCode,
  kvChatForClient,
  kvClientForChat,
  kvConnectCode,
  parseCallbackData,
  TELEGRAM_MESSAGE_LIMIT,
} from "@/lib/telegram";
import type { GoEnv } from "@/lib/types";
import { makeMockKV } from "./harness";

// All Telegram coverage is SYNTHETIC: updates are forged locally and authenticated with
// the same secret header Telegram would echo. No live bot, no deploy — E2E is deploy day.

const BOT_TOKEN = "123456:TEST-TOKEN";
const HOOK_SECRET = "test-webhook-secret";
const CLIENT_ID = "client-test";
const APPROVAL_ID = "AbCdEfGhIjKlMnOpQrStUv";
const CHAT_ID = 777;

function makeRecord(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    id: APPROVAL_ID,
    agentId: "agent-test",
    sessionId: "session-test",
    actionSummary: "Send €120 refund to customer #991",
    actionPayload: { tool: "stripe.refund", args: { amount: 12000 } },
    actionPayloadHash: "c".repeat(64),
    status: "pending",
    responderId: null,
    reason: null,
    channels: ["telegram"],
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    decidedAt: null,
    callbackUrl: null,
    ...overrides,
  };
}

interface TgCall {
  method: string;
  payload: Record<string, unknown>;
}

function stubTelegramFetch(): TgCall[] {
  const calls: TgCall[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const match = /api\.telegram\.org\/bot[^/]+\/(\w+)$/.exec(String(input));
    if (!match) throw new Error(`Unexpected fetch: ${String(input)}`);
    calls.push({
      method: match[1] as string,
      payload: JSON.parse(String(init?.body)) as Record<string, unknown>,
    });
    return Response.json({ ok: true, result: {} });
  });
  return calls;
}

function makeEnv(overrides: Partial<GoEnv> = {}): GoEnv {
  return {
    AUDIT: {
      getApproval: async () => makeRecord(),
      decideApproval: vi.fn(
        async (params: {
          decision: "approved" | "denied";
          reason?: string;
          responderId?: string;
        }): Promise<DecideResult> => ({
          ok: true,
          record: makeRecord({
            status: params.decision,
            reason: params.reason ?? null,
            responderId: params.responderId ?? null,
            decidedAt: new Date().toISOString(),
          }),
        }),
      ),
    },
    CHANNELS_KV: makeMockKV(),
    TELEGRAM_BOT_TOKEN: BOT_TOKEN,
    TELEGRAM_WEBHOOK_SECRET: HOOK_SECRET,
    ...overrides,
  };
}

function webhookPost(update: unknown, secret: string | null = HOOK_SECRET): Request {
  return new Request("https://go.kajaril.com/tg/webhook", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(secret === null ? {} : { "X-Telegram-Bot-Api-Secret-Token": secret }),
    },
    body: JSON.stringify(update),
  });
}

const ctx = {} as ExecutionContext;

afterEach(() => {
  vi.unstubAllGlobals();
});

// --- pure helpers ---

describe("telegram helpers", () => {
  it("parses every callback verb and rejects garbage", () => {
    expect(parseCallbackData(`ap:${APPROVAL_ID}`)).toEqual({
      verb: "approve",
      approvalId: APPROVAL_ID,
    });
    expect(parseCallbackData(`dn:${APPROVAL_ID}`)).toEqual({
      verb: "deny",
      approvalId: APPROVAL_ID,
    });
    expect(parseCallbackData(`dr:${APPROVAL_ID}`)).toEqual({
      verb: "deny_reason",
      approvalId: APPROVAL_ID,
    });
    expect(parseCallbackData(undefined)).toBeNull();
    expect(parseCallbackData("")).toBeNull();
    expect(parseCallbackData("xx:abc")).toBeNull();
    expect(parseCallbackData("ap:")).toBeNull();
    expect(parseCallbackData("ap:has space")).toBeNull();
    // 64-byte callback_data cap: verb + colon + 62 chars would exceed it
    expect(parseCallbackData(`ap:${"a".repeat(62)}`)).toBeNull();
  });

  it("builds a card that names the agent, summary, tool, hash and link", () => {
    const url = "https://go.kajaril.com/a/v1.abc.def";
    const card = buildApprovalCard(makeRecord(), url);
    expect(card).toContain("agent-test");
    expect(card).toContain("Send €120 refund to customer #991");
    expect(card).toContain("Tool: stripe.refund");
    expect(card).toContain(`Action hash: ${"c".repeat(64)}`);
    expect(card).toContain(url);
    expect(card.length).toBeLessThanOrEqual(TELEGRAM_MESSAGE_LIMIT);
  });

  it("truncates oversized args but keeps the hash and link intact", () => {
    const record = makeRecord({
      actionPayload: { tool: "bulk.update", args: { blob: "x".repeat(4000) } },
    });
    const url = "https://go.kajaril.com/a/v1.abc.def";
    const card = buildApprovalCard(record, url);
    expect(card.length).toBeLessThanOrEqual(TELEGRAM_MESSAGE_LIMIT);
    expect(card).toContain("[truncated — full payload on the approval page]");
    expect(card).toContain(`Action hash: ${"c".repeat(64)}`);
    expect(card).toContain(url);
  });

  it("extracts the bot id from the token and compares secrets in constant time", () => {
    expect(botIdFromToken(BOT_TOKEN)).toBe("123456");
    expect(botIdFromToken("malformed")).toBe("");
    expect(constantTimeEqualString(HOOK_SECRET, HOOK_SECRET)).toBe(true);
    expect(constantTimeEqualString(HOOK_SECRET, "test-webhook-secreT")).toBe(false);
    expect(constantTimeEqualString(HOOK_SECRET, "short")).toBe(false);
  });
});

// --- webhook gate ---

describe("POST /tg/webhook — gate", () => {
  it("fails closed (503) when the channel is not configured", async () => {
    stubTelegramFetch();
    const env = makeEnv({ TELEGRAM_WEBHOOK_SECRET: undefined });
    const res = await worker.fetch(webhookPost({}), env, ctx);
    expect(res.status).toBe(503);
  });

  it("rejects a missing or wrong secret header before parsing anything", async () => {
    stubTelegramFetch();
    const env = makeEnv();
    expect((await worker.fetch(webhookPost({}, null), env, ctx)).status).toBe(401);
    expect((await worker.fetch(webhookPost({}, "forged"), env, ctx)).status).toBe(401);
    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
  });

  it("acknowledges an authenticated but unparseable body without processing", async () => {
    stubTelegramFetch();
    const env = makeEnv();
    const req = new Request("https://go.kajaril.com/tg/webhook", {
      method: "POST",
      headers: { "X-Telegram-Bot-Api-Secret-Token": HOOK_SECRET },
      body: "not json",
    });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
  });
});

// --- connect deep-link flow ---

describe("POST /tg/webhook — /start connect flow", () => {
  function startUpdate(text: string, chatId = CHAT_ID) {
    return {
      update_id: 1,
      message: { message_id: 10, text, chat: { id: chatId }, from: { id: 42 } },
    };
  }

  it("redeems a one-time code: binds both directions, deletes the code, confirms", async () => {
    const calls = stubTelegramFetch();
    const env = makeEnv();
    const kv = env.CHANNELS_KV as NonNullable<GoEnv["CHANNELS_KV"]>;
    const code = generateConnectCode();
    await kv.put(kvConnectCode(code), CLIENT_ID);

    const res = await worker.fetch(webhookPost(startUpdate(`/start ${code}`)), env, ctx);
    expect(res.status).toBe(200);
    expect(await kv.get(kvChatForClient(CLIENT_ID))).toBe(String(CHAT_ID));
    expect(await kv.get(kvClientForChat(CHAT_ID))).toBe(CLIENT_ID);
    expect(await kv.get(kvConnectCode(code))).toBeNull();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("sendMessage");
    expect(String(calls[0]?.payload.text)).toContain(CLIENT_ID);
  });

  it("rejects an unknown or expired code without writing any binding", async () => {
    const calls = stubTelegramFetch();
    const env = makeEnv();
    const kv = env.CHANNELS_KV as NonNullable<GoEnv["CHANNELS_KV"]>;

    const res = await worker.fetch(
      webhookPost(startUpdate(`/start ${generateConnectCode()}`)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await kv.get(kvClientForChat(CHAT_ID))).toBeNull();
    expect(String(calls[0]?.payload.text)).toContain("invalid or has expired");
  });

  it("re-connecting to a new chat removes the stale reverse binding", async () => {
    stubTelegramFetch();
    const env = makeEnv();
    const kv = env.CHANNELS_KV as NonNullable<GoEnv["CHANNELS_KV"]>;
    await kv.put(kvChatForClient(CLIENT_ID), "111");
    await kv.put(kvClientForChat(111), CLIENT_ID);
    const code = generateConnectCode();
    await kv.put(kvConnectCode(code), CLIENT_ID);

    await worker.fetch(webhookPost(startUpdate(`/start ${code}`)), env, ctx);
    expect(await kv.get(kvClientForChat(111))).toBeNull();
    expect(await kv.get(kvChatForClient(CLIENT_ID))).toBe(String(CHAT_ID));
    expect(await kv.get(kvClientForChat(CHAT_ID))).toBe(CLIENT_ID);
  });
});

// --- callback decisions ---

describe("POST /tg/webhook — inline button callbacks", () => {
  function callbackUpdate(data: string, chatId = CHAT_ID) {
    return {
      update_id: 2,
      callback_query: {
        id: "cb-1",
        data,
        from: { id: 42 },
        message: { message_id: 11, chat: { id: chatId }, text: "⚖️ Approval requested …" },
      },
    };
  }

  async function boundEnv(): Promise<GoEnv> {
    const env = makeEnv();
    const kv = env.CHANNELS_KV as NonNullable<GoEnv["CHANNELS_KV"]>;
    await kv.put(kvClientForChat(CHAT_ID), CLIENT_ID);
    return env;
  }

  it("approve button decides within the bound tenant with a telegram responder id", async () => {
    const calls = stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(callbackUpdate(`ap:${APPROVAL_ID}`)), env, ctx);

    expect(env.AUDIT.decideApproval).toHaveBeenCalledWith({
      clientId: CLIENT_ID,
      approvalId: APPROVAL_ID,
      decision: "approved",
      responderId: "telegram:42",
    });
    const methods = calls.map((c) => c.method);
    expect(methods).toContain("answerCallbackQuery");
    expect(methods).toContain("editMessageText");
    const edit = calls.find((c) => c.method === "editMessageText");
    expect(String(edit?.payload.text)).toContain("✅ Approved");
    expect(edit?.payload.reply_markup).toBeUndefined();
  });

  it("deny button decides denied", async () => {
    stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(callbackUpdate(`dn:${APPROVAL_ID}`)), env, ctx);
    expect(env.AUDIT.decideApproval).toHaveBeenCalledWith(
      expect.objectContaining({ decision: "denied", clientId: CLIENT_ID }),
    );
  });

  it("deny-with-reason sends a ForceReply prompt carrying the ref — no decision yet", async () => {
    const calls = stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(callbackUpdate(`dr:${APPROVAL_ID}`)), env, ctx);

    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
    const prompt = calls.find((c) => c.method === "sendMessage");
    expect(String(prompt?.payload.text)).toContain(`ref:${APPROVAL_ID}`);
    expect(prompt?.payload.reply_markup).toEqual({ force_reply: true });
  });

  it("an unbound chat can never reach decideApproval", async () => {
    const calls = stubTelegramFetch();
    const env = makeEnv();
    await worker.fetch(webhookPost(callbackUpdate(`ap:${APPROVAL_ID}`)), env, ctx);
    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
    expect(String(calls[0]?.payload.text)).toContain("not connected");
  });

  it("malformed callback_data from a hostile client is refused at parse time", async () => {
    stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(callbackUpdate("ap:../../etc")), env, ctx);
    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
  });

  it("a second tap on an already-decided approval reports the terminal state", async () => {
    const calls = stubTelegramFetch();
    const env = await boundEnv();
    env.AUDIT.decideApproval = vi.fn(async () => ({
      ok: false,
      reason: "already_decided" as const,
      record: makeRecord({ status: "denied", decidedAt: new Date().toISOString() }),
    }));
    await worker.fetch(webhookPost(callbackUpdate(`ap:${APPROVAL_ID}`)), env, ctx);
    const answer = calls.find((c) => c.method === "answerCallbackQuery");
    expect(String(answer?.payload.text)).toContain("Denied");
  });
});

// --- deny-with-reason reply ---

describe("POST /tg/webhook — reason reply", () => {
  function replyUpdate(
    opts: { reason?: string; promptText?: string; promptFromId?: number; isBot?: boolean } = {},
  ) {
    return {
      update_id: 3,
      message: {
        message_id: 12,
        text: opts.reason ?? "Refund exceeds the customer's lifetime value",
        chat: { id: CHAT_ID },
        from: { id: 42 },
        reply_to_message: {
          message_id: 11,
          text: opts.promptText ?? buildReasonPrompt(APPROVAL_ID),
          from: { id: opts.promptFromId ?? 123456, is_bot: opts.isBot ?? true },
        },
      },
    };
  }

  async function boundEnv(): Promise<GoEnv> {
    const env = makeEnv();
    const kv = env.CHANNELS_KV as NonNullable<GoEnv["CHANNELS_KV"]>;
    await kv.put(kvClientForChat(CHAT_ID), CLIENT_ID);
    return env;
  }

  it("a reply to our prompt denies with the reason attached", async () => {
    const calls = stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(replyUpdate()), env, ctx);

    expect(env.AUDIT.decideApproval).toHaveBeenCalledWith({
      clientId: CLIENT_ID,
      approvalId: APPROVAL_ID,
      decision: "denied",
      reason: "Refund exceeds the customer's lifetime value",
      responderId: "telegram:42",
    });
    expect(String(calls.find((c) => c.method === "sendMessage")?.payload.text)).toContain(
      "❌ Denied",
    );
  });

  it("ignores replies quoting a message that is not from our bot", async () => {
    stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(replyUpdate({ promptFromId: 999999 })), env, ctx);
    await worker.fetch(webhookPost(replyUpdate({ isBot: false })), env, ctx);
    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
  });

  it("ignores replies whose quoted text carries no ref line", async () => {
    stubTelegramFetch();
    const env = await boundEnv();
    await worker.fetch(webhookPost(replyUpdate({ promptText: "unrelated bot message" })), env, ctx);
    expect(env.AUDIT.decideApproval).not.toHaveBeenCalled();
  });
});
