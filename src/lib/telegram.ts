import type { ApprovalInternalClient, ApprovalRecord } from "@/lib/approval";
import { MAX_REASON_CHARS } from "@/lib/approval";
import { canonicalJson } from "@/lib/hash";

// Telegram channel (D4, instant tier). Three flows, all built on one invariant:
// nothing user-supplied selects a tenant.
//
//   connect — an ADMIN-authenticated call on the gated worker mints a one-time code
//     (CSPRNG, 15-min TTL in CHANNELS_KV) baked into a t.me deep link. The bot's
//     /start <code> webhook redeems it: code → clientId, then the chat↔tenant binding
//     is written in both directions. The tenant was chosen by the admin call, never
//     by the Telegram user.
//   send — the gated worker resolves clientId → chat_id from the binding and posts the
//     approval card with inline Approve / Deny / Deny-with-reason buttons.
//   decide — callback updates resolve chat_id → clientId from the stored binding and
//     go through ApprovalInternal.decideApproval. callback_data is capped at 64 bytes
//     by Telegram, far too small for an HMAC link token, so it carries only the verb +
//     approvalId — both treated as untrusted: shape-checked, and only ever used inside
//     the tenant the chat is bound to. A forged approvalId can at worst decide another
//     approval of the SAME tenant, which the chat's owner is authorized to do anyway.
//
// Updates are trusted only because the webhook checked X-Telegram-Bot-Api-Secret-Token
// (our value, registered via setWebhook) before anything here runs.

export const TELEGRAM_SECRET_TOKEN_HEADER = "X-Telegram-Bot-Api-Secret-Token";
export const CONNECT_CODE_TTL_SECONDS = 15 * 60;
export const TELEGRAM_MESSAGE_LIMIT = 4096;
const API_BASE = "https://api.telegram.org";
const API_TIMEOUT_MS = 10_000;

// --- CHANNELS_KV key layout (telegram side; email lives in notify.ts) ---

export function kvConnectCode(code: string): string {
  return `tg:connect:${code}`;
}
export function kvChatForClient(clientId: string): string {
  return `tg:client:${clientId}`;
}
export function kvClientForChat(chatId: number | string): string {
  return `tg:chat:${chatId}`;
}

// 16 bytes of CSPRNG output, base64url — same strength reasoning as approval ids, but a
// connect code IS a capability (it binds a chat to a tenant), hence single-use + TTL.
// 22 chars also fits Telegram's 64-char limit on the ?start= deep-link parameter.
export function generateConnectCode(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// Constant-time comparison for the webhook secret. Length is compared first — it leaks
// only length, and the secret is high-entropy random, so that reveals nothing useful.
export function constantTimeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// --- callback data ---
// ap = approve, dn = deny, dr = deny-with-reason (sends a ForceReply prompt). Our ids are
// 22 chars; anything that would push callback_data past Telegram's 64-byte cap is refused
// at parse time by the same regex.

const CALLBACK_RE = /^(ap|dn|dr):([A-Za-z0-9_-]{1,61})$/;

export type CallbackVerb = "approve" | "deny" | "deny_reason";

export function parseCallbackData(
  data: string | undefined,
): { verb: CallbackVerb; approvalId: string } | null {
  if (typeof data !== "string") return null;
  const match = CALLBACK_RE.exec(data);
  if (!match) return null;
  const [, code, approvalId] = match as unknown as [string, string, string];
  const verb: CallbackVerb = code === "ap" ? "approve" : code === "dn" ? "deny" : "deny_reason";
  return { verb, approvalId };
}

// The reason-prompt carries its approvalId in a trailing ref line so the reply handler is
// stateless: Telegram echoes the full prompt back inside reply_to_message. Trusting that
// text is safe because the handler also checks the quoted message was authored by OUR bot,
// and a forged ref could only ever deny an approval of the chat's own tenant.
const REASON_PROMPT_REF_RE = /\nref:([A-Za-z0-9_-]{1,61})$/;

export function buildReasonPrompt(approvalId: string): string {
  return `Reply to this message with the denial reason (it is recorded with the decision).\nref:${approvalId}`;
}

// Bot tokens are "<bot id>:<secret>" — the public half identifies our own messages in
// reply_to_message without a getMe round-trip.
export function botIdFromToken(botToken: string): string {
  const sep = botToken.indexOf(":");
  return sep > 0 ? botToken.slice(0, sep) : "";
}

// --- approval card ---

export function approvalKeyboard(approvalId: string): unknown {
  return {
    inline_keyboard: [
      [
        { text: "✅ Approve", callback_data: `ap:${approvalId}` },
        { text: "❌ Deny", callback_data: `dn:${approvalId}` },
      ],
      [{ text: "✍️ Deny with reason…", callback_data: `dr:${approvalId}` }],
    ],
  };
}

const ARGS_TRUNCATION_NOTICE = "… [truncated — full payload on the approval page]";

// Plain text on purpose: no parse_mode means no escaping rules, so attacker-influenced
// fields (summary, args) can never break formatting or smuggle entities. The args render
// is the canonical JSON that was hashed (D6); if it must be truncated to fit Telegram's
// 4096-char limit, the hash and the approval-page link still bind the full payload.
export function buildApprovalCard(
  record: ApprovalRecord,
  approvalUrl: string | null,
  nowMs: number = Date.now(),
): string {
  const expiresMin = Math.max(1, Math.round((Date.parse(record.expiresAt) - nowMs) / 60_000));

  const head = ["⚖️ Approval requested", "", `Agent: ${record.agentId}`, "", record.actionSummary];
  const tail: string[] = [];
  if (record.actionPayloadHash) {
    tail.push("", `Action hash: ${record.actionPayloadHash}`);
  }
  tail.push("", `Expires in ~${expiresMin} min.`);
  if (approvalUrl) {
    tail.push(`Details & web decision: ${approvalUrl}`);
  }

  const middle: string[] = [];
  if (record.actionPayload) {
    middle.push("", `Tool: ${record.actionPayload.tool}`);
    if (record.actionPayload.args !== undefined) {
      const argsJson = canonicalJson(record.actionPayload.args);
      const used = [...head, ...middle, "Args: ", ...tail].join("\n").length;
      const budget = TELEGRAM_MESSAGE_LIMIT - used;
      middle.push(
        `Args: ${
          argsJson.length <= budget
            ? argsJson
            : argsJson.slice(0, Math.max(0, budget - ARGS_TRUNCATION_NOTICE.length)) +
              ARGS_TRUNCATION_NOTICE
        }`,
      );
    }
  }

  return [...head, ...middle, ...tail].join("\n");
}

function outcomeLine(record: ApprovalRecord): string {
  const at = record.decidedAt ? ` · ${new Date(record.decidedAt).toUTCString()}` : "";
  const by = record.responderId ? ` by ${record.responderId}` : "";
  switch (record.status) {
    case "approved":
      return `✅ Approved${by}${at} — witnessed.`;
    case "denied":
      return `❌ Denied${by}${at}${record.reason ? `\nReason: ${record.reason}` : ""} — witnessed.`;
    case "timeout":
      return "⌛️ Expired before a decision.";
    default:
      return "Still pending.";
  }
}

// --- Telegram Bot API ---

export type TelegramSendStatus = "sent" | "failed";

// Best-effort, never throws. The token rides in the URL, so neither the URL nor the error
// body is ever logged — method name and status only.
async function tgApi(botToken: string, method: string, payload: unknown): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/bot${botToken}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
    if (!res.ok) console.error(`telegram ${method} returned ${res.status}`);
    return res.ok;
  } catch (e) {
    console.error(`telegram ${method} failed: ${e instanceof Error ? e.message : "error"}`);
    return false;
  }
}

export async function sendApprovalCard(
  botToken: string,
  chatId: string,
  record: ApprovalRecord,
  approvalUrl: string | null,
): Promise<TelegramSendStatus> {
  const ok = await tgApi(botToken, "sendMessage", {
    chat_id: chatId,
    text: buildApprovalCard(record, approvalUrl),
    disable_web_page_preview: true,
    reply_markup: approvalKeyboard(record.id),
  });
  return ok ? "sent" : "failed";
}

// --- webhook update processing ---

export interface TelegramUpdate {
  message?: {
    message_id: number;
    text?: string;
    chat: { id: number };
    from?: { id: number; is_bot?: boolean };
    reply_to_message?: {
      message_id: number;
      text?: string;
      from?: { id: number; is_bot?: boolean };
    };
  };
  callback_query?: {
    id: string;
    data?: string;
    from: { id: number };
    message?: { message_id: number; chat: { id: number }; text?: string };
  };
}

export interface TelegramWebhookDeps {
  audit: ApprovalInternalClient;
  kv: KVNamespace;
  botToken: string;
}

function clampMessage(text: string): string {
  return text.length <= TELEGRAM_MESSAGE_LIMIT ? text : text.slice(0, TELEGRAM_MESSAGE_LIMIT);
}

export async function processTelegramUpdate(
  deps: TelegramWebhookDeps,
  update: TelegramUpdate,
): Promise<void> {
  if (update.callback_query) {
    await handleCallback(deps, update.callback_query);
    return;
  }
  const msg = update.message;
  if (!msg?.text || !msg.from || msg.from.is_bot) return;
  if (msg.text.startsWith("/start")) {
    await handleStart(deps, msg);
    return;
  }
  if (msg.reply_to_message) {
    await handleReasonReply(deps, msg);
  }
}

type TelegramMessage = NonNullable<TelegramUpdate["message"]>;
type TelegramCallback = NonNullable<TelegramUpdate["callback_query"]>;

async function reply(deps: TelegramWebhookDeps, chatId: number, text: string): Promise<void> {
  await tgApi(deps.botToken, "sendMessage", { chat_id: chatId, text: clampMessage(text) });
}

async function handleStart(deps: TelegramWebhookDeps, msg: TelegramMessage): Promise<void> {
  const code = (msg.text ?? "").slice("/start".length).trim();
  if (!code) {
    await reply(
      deps,
      msg.chat.id,
      "This bot delivers kajaril approval requests. Connect it with the one-time link from POST /channels/telegram/connect.",
    );
    return;
  }
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(code)) return;

  const clientId = await deps.kv.get(kvConnectCode(code));
  if (!clientId) {
    await reply(
      deps,
      msg.chat.id,
      "This connect link is invalid or has expired. Mint a fresh one and try again.",
    );
    return;
  }
  // Single-use: the code dies before the binding is written.
  await deps.kv.delete(kvConnectCode(code));

  const chatId = String(msg.chat.id);
  // A binding overwrite must not leave a stale reverse entry behind: a previously-bound
  // chat could otherwise still decide for this tenant, and a previously-bound tenant
  // would keep sending cards into a chat that can no longer decide them.
  const prevChat = await deps.kv.get(kvChatForClient(clientId));
  if (prevChat && prevChat !== chatId) await deps.kv.delete(kvClientForChat(prevChat));
  const prevClient = await deps.kv.get(kvClientForChat(chatId));
  if (prevClient && prevClient !== clientId) await deps.kv.delete(kvChatForClient(prevClient));

  await deps.kv.put(kvChatForClient(clientId), chatId);
  await deps.kv.put(kvClientForChat(chatId), clientId);
  await reply(
    deps,
    msg.chat.id,
    `Connected. Approval requests for ${clientId} will arrive in this chat.`,
  );
}

async function answerCallback(
  deps: TelegramWebhookDeps,
  callbackId: string,
  text: string,
): Promise<void> {
  await tgApi(deps.botToken, "answerCallbackQuery", { callback_query_id: callbackId, text });
}

async function handleCallback(deps: TelegramWebhookDeps, cb: TelegramCallback): Promise<void> {
  const parsed = parseCallbackData(cb.data);
  const chatId = cb.message?.chat.id;
  if (!parsed || chatId === undefined) {
    await answerCallback(deps, cb.id, "This button is no longer valid.");
    return;
  }

  const clientId = await deps.kv.get(kvClientForChat(chatId));
  if (!clientId) {
    await answerCallback(deps, cb.id, "This chat is not connected to a kajaril tenant.");
    return;
  }

  if (parsed.verb === "deny_reason") {
    await answerCallback(deps, cb.id, "Reply to the prompt with your reason.");
    await tgApi(deps.botToken, "sendMessage", {
      chat_id: chatId,
      text: buildReasonPrompt(parsed.approvalId),
      reply_markup: { force_reply: true },
    });
    return;
  }

  const result = await deps.audit.decideApproval({
    clientId,
    approvalId: parsed.approvalId,
    decision: parsed.verb === "approve" ? "approved" : "denied",
    responderId: `telegram:${cb.from.id}`,
  });

  if (result.ok && result.record) {
    await answerCallback(
      deps,
      cb.id,
      result.record.status === "approved" ? "✅ Approved" : "❌ Denied",
    );
  } else if (result.record) {
    await answerCallback(deps, cb.id, outcomeLine(result.record));
  } else {
    await answerCallback(deps, cb.id, "Approval not found.");
    return;
  }

  // Replace the card's buttons with the outcome so the chat shows a closed loop and a
  // second tap has nothing to press. Best-effort: the decision is already committed.
  if (cb.message) {
    const base = cb.message.text ?? result.record.actionSummary;
    await tgApi(deps.botToken, "editMessageText", {
      chat_id: chatId,
      message_id: cb.message.message_id,
      text: clampMessage(`${base}\n\n${outcomeLine(result.record)}`),
    });
  }
}

async function handleReasonReply(deps: TelegramWebhookDeps, msg: TelegramMessage): Promise<void> {
  const replied = msg.reply_to_message;
  if (!replied?.from?.is_bot) return;
  // Only OUR bot's prompts count — a reply quoting someone else's "ref:" text is ignored.
  const botId = botIdFromToken(deps.botToken);
  if (!botId || String(replied.from.id) !== botId) return;

  const match = REASON_PROMPT_REF_RE.exec(replied.text ?? "");
  if (!match) return;
  const approvalId = match[1] as string;

  const clientId = await deps.kv.get(kvClientForChat(msg.chat.id));
  if (!clientId) return;

  const reason = (msg.text ?? "").trim().slice(0, MAX_REASON_CHARS);
  if (!reason || !msg.from) return;

  const result = await deps.audit.decideApproval({
    clientId,
    approvalId,
    decision: "denied",
    reason,
    responderId: `telegram:${msg.from.id}`,
  });

  if (result.ok && result.record) {
    await reply(deps, msg.chat.id, outcomeLine(result.record));
  } else if (result.record) {
    await reply(deps, msg.chat.id, `No longer pending — ${outcomeLine(result.record)}`);
  } else {
    await reply(deps, msg.chat.id, "Approval not found.");
  }
}
