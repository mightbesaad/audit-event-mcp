import type { ApprovalCreateResult, ApprovalRecord } from "@/lib/approval";
import {
  EMAIL_ESCALATION_DELAY_SECONDS,
  isValidApprovalIdShape,
  isValidClientIdShape,
} from "@/lib/approval";
import { kvEmailForClient } from "@/lib/notify";
import { kvChatForClient, sendApprovalCard } from "@/lib/telegram";
import { APPROVAL_LINK_GRACE_SECONDS, mintApprovalToken } from "@/lib/token";
import type { Env, RecordResult } from "@/lib/types";
import { deriveWebhookSecret } from "@/lib/webhook";

// Worker-layer request_approval flow (Day 3 wires the MCP tool / REST route to this).
// Shape kept from gvnr src/routes/approval.ts (donor): REST-first {status, body} results
// that MCP wrappers can pass through unchanged.
//
// This is where approval.requested enters the chain (D7): the DO's create handler stays
// pure approval storage, and the event rides the existing /record path so the chain format,
// verify_chain, and the notary stay untouched.

export interface FlowResult {
  status: number;
  body: unknown;
}

// DO name derivation lives here (module scope, not on any RPC-exposed class — see the
// stubFor note in src/main.ts). clientId must already come from a verified source:
// CF Access JWT today, HMAC link token on the go worker.
export function tenantStub(env: Env, clientId: string): DurableObjectStub {
  const doId = env.AUDIT_DO.idFromName(`audit-do-${clientId}`);
  return env.AUDIT_DO.get(doId);
}

const REQUESTED_PURPOSE = "human oversight — approval requested (AI Act Art. 14)";

// Public constant, not config: the production approve page lives on the go worker (D1).
// Self-hosters point APPROVAL_LINK_BASE_URL at their own deployment.
const DEFAULT_APPROVAL_LINK_BASE = "https://go.kajaril.com";

// Every public human-facing link (approval pages, dossier downloads since Day 5) points at
// the go worker — one base, one override for self-hosters.
export function publicLinkBase(env: Env): string {
  return (env.APPROVAL_LINK_BASE_URL ?? DEFAULT_APPROVAL_LINK_BASE).replace(/\/+$/, "");
}

// One mint path for every surface that hands a human the link (request_approval response,
// telegram card, escalation email). The token's exp outlives the approval's expires_at by
// the grace window (token.ts) so late clickers get a terminal-state page, not "invalid
// link". Null when the secret is unbound — the approval still works via polling.
export async function mintApprovalUrl(
  env: Env,
  clientId: string,
  approvalId: string,
  expiresAt: string,
): Promise<string | null> {
  if (!env.APPROVAL_TOKEN_SECRET) return null;
  const base = publicLinkBase(env);
  const token = await mintApprovalToken(env.APPROVAL_TOKEN_SECRET, {
    clientId,
    approvalId,
    exp: Math.floor(Date.parse(expiresAt) / 1000) + APPROVAL_LINK_GRACE_SECONDS,
  });
  return `${base}/a/${token}`;
}

// What request_approval reports about each requested channel (D4). Creation-response
// fields are additive (webhookSecret set the precedent); the decision wire contract (D5)
// is untouched. "push" stays unreported until the Web Push twin exists (v1.5).
export interface ChannelDispatch {
  telegram: "sent" | "failed" | "not_connected" | "unconfigured" | "not_requested";
  email:
    | "immediate"
    | "scheduled"
    | "expires_first"
    | "no_address"
    | "unconfigured"
    | "arm_failed"
    | "not_requested";
}

// Channel ladder dispatch (D4), awaited inline: the email decision needs to know whether
// an instant channel actually reached someone, and an approval card that silently failed
// to send would make the "sent" claim in the response a lie. Telegram failures degrade,
// never block — the approval exists and polls fine regardless.
async function dispatchChannels(
  env: Env,
  clientId: string,
  record: ApprovalRecord,
  approvalUrl: string | null,
): Promise<ChannelDispatch> {
  const dispatch: ChannelDispatch = { telegram: "not_requested", email: "not_requested" };

  if (record.channels.includes("telegram")) {
    if (!env.TELEGRAM_BOT_TOKEN || !env.CHANNELS_KV) {
      dispatch.telegram = "unconfigured";
    } else {
      const chatId = await env.CHANNELS_KV.get(kvChatForClient(clientId));
      dispatch.telegram = chatId
        ? await sendApprovalCard(env.TELEGRAM_BOT_TOKEN, chatId, record, approvalUrl)
        : "not_connected";
    }
  }

  if (record.channels.includes("email")) {
    if (!env.RESEND_API_KEY || !env.CHANNELS_KV) {
      dispatch.email = "unconfigured";
    } else {
      const address = await env.CHANNELS_KV.get(kvEmailForClient(clientId));
      if (!address) {
        dispatch.email = "no_address";
      } else {
        // "Unacked" for v1 means undecided: a card the approver saw and is thinking about
        // still escalates at 10 min — better a redundant email than a silent timeout.
        const instant = dispatch.telegram === "sent";
        const dueAtMs = instant ? Date.now() + EMAIL_ESCALATION_DELAY_SECONDS * 1000 : Date.now();
        if (dueAtMs >= Date.parse(record.expiresAt)) {
          dispatch.email = "expires_first";
        } else {
          const armRes = await tenantStub(env, clientId).fetch(
            "https://do-internal/approval/arm-escalation",
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ approvalId: record.id, clientId, emailTo: address, dueAtMs }),
            },
          );
          dispatch.email = armRes.ok ? (instant ? "scheduled" : "immediate") : "arm_failed";
        }
      }
    }
  }

  return dispatch;
}

export async function requestApproval(
  env: Env,
  clientId: string,
  input: unknown,
): Promise<FlowResult> {
  // Defense-in-depth, same as ApprovalInternal: a malformed clientId never becomes a DO name.
  if (!isValidClientIdShape(clientId)) {
    return { status: 400, body: { error: "invalid_client" } };
  }

  // Per-tenant rate limit (donor pattern): caps an attacker or buggy agent at 30 approval
  // creations a minute. Each approval costs DO writes, a chain event, and (Day 4) a channel
  // send — shared capacity one tenant must not drain.
  if (env.APPROVAL_RATE_LIMITER) {
    const { success } = await env.APPROVAL_RATE_LIMITER.limit({ key: `req:${clientId}` });
    if (!success) {
      return {
        status: 429,
        body: {
          error: "rate_limited",
          retryable: true,
          retry_after_ms: 60_000,
          limit: "30 request_approval calls per minute",
        },
      };
    }
  }

  const stub = tenantStub(env, clientId);

  const createRes = await stub.fetch("https://do-internal/approval/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!createRes.ok) {
    return { status: createRes.status, body: await createRes.json() };
  }
  const created = (await createRes.json()) as ApprovalCreateResult;
  const record = created.record;

  // The witnessed half of the request: everything the human will be shown, bound into the
  // chain via the /record input hash. If this fails the approval still exists but is
  // unwitnessed — fail loudly so the agent retries; the orphan stays pending and expires.
  const recordRes = await stub.fetch("https://do-internal/record", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agentId: record.agentId,
      sessionId: record.sessionId,
      eventType: "approval.requested",
      purpose: REQUESTED_PURPOSE,
      input: {
        approvalId: created.approvalId,
        actionSummary: record.actionSummary,
        actionPayload: record.actionPayload,
        actionPayloadHash: record.actionPayloadHash,
        channels: record.channels,
        expiresAt: record.expiresAt,
        callbackUrl: record.callbackUrl,
      },
    }),
  });
  if (!recordRes.ok) {
    return {
      status: 500,
      body: {
        error: "chain_event_failed",
        detail: "approval was created but could not be witnessed — retry request_approval",
      },
    };
  }
  const chainEvent = (await recordRes.json()) as RecordResult;

  const approvalUrl = await mintApprovalUrl(env, clientId, created.approvalId, created.expiresAt);

  // Channel ladder (D4): telegram card now, email escalation armed in the tenant DO.
  // Runs after the chain event so a witnessed approval is never invisible to its approver
  // only because a channel hiccuped — failures are reported, not thrown.
  const notifications = await dispatchChannels(env, clientId, record, approvalUrl);

  return {
    status: 200,
    body: {
      approvalId: created.approvalId,
      status: record.status,
      expiresAt: created.expiresAt,
      actionPayloadHash: record.actionPayloadHash,
      approvalUrl,
      notifications,
      chainEvent,
      // D9 distribution channel: the per-tenant webhook verification secret travels in
      // every response so v1 needs no dashboard. Null when the master secret is unbound —
      // in that case decision webhooks are not sent at all (fail closed, never unsigned).
      webhookSecret: env.WEBHOOK_SIGNING_SECRET
        ? await deriveWebhookSecret(env.WEBHOOK_SIGNING_SECRET, clientId)
        : null,
    },
  };
}

// Worker-layer check_approval flow: reads via the tenant stub and the DO's /approval/get —
// deliberately NOT via ApprovalInternal, whose get/decide surface belongs to the go worker
// alone and must not widen. Status is computed on read by the DO, so 'timeout' appears here
// the moment expires_at passes. The poll body is the narrow wire contract (D5) plus the
// fields needed to display/verify the decision — never callbackUrl or channel internals.
export async function checkApproval(
  env: Env,
  clientId: string,
  approvalId: string,
): Promise<FlowResult> {
  if (!isValidClientIdShape(clientId)) {
    return { status: 400, body: { error: "invalid_client" } };
  }
  // Malformed ids can't exist, so they are indistinguishable from absent ones.
  if (!isValidApprovalIdShape(approvalId)) {
    return { status: 404, body: { error: "approval_not_found" } };
  }

  const res = await tenantStub(env, clientId).fetch("https://do-internal/approval/get", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approvalId }),
  });
  if (res.status === 400 || res.status === 404) {
    return { status: 404, body: { error: "approval_not_found" } };
  }
  if (!res.ok) {
    return { status: 500, body: { error: "approval_get_failed" } };
  }
  const record = (await res.json()) as ApprovalRecord;

  return {
    status: 200,
    body: {
      approvalId: record.id,
      status: record.status,
      reason: record.reason,
      responderId: record.responderId,
      actionSummary: record.actionSummary,
      actionPayloadHash: record.actionPayloadHash,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      decidedAt: record.decidedAt,
    },
  };
}

const DECIDED_PURPOSE = "human oversight — approval decided (AI Act Art. 14)";

// Emits the approval.decided chain event after a successful decide. The decision is already
// committed in the approvals table by then, so a /record failure is logged loudly and
// reported as null rather than thrown — the human's decision must not appear to fail.
// A retrying outbox is v1.5 (DEFERRED.md).
export async function witnessDecision(
  env: Env,
  clientId: string,
  record: ApprovalRecord,
): Promise<RecordResult | null> {
  try {
    const res = await tenantStub(env, clientId).fetch("https://do-internal/record", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId: record.agentId,
        sessionId: record.sessionId,
        eventType: "approval.decided",
        purpose: DECIDED_PURPOSE,
        input: {
          approvalId: record.id,
          decision: record.status,
          reason: record.reason,
          responderId: record.responderId,
          actionPayloadHash: record.actionPayloadHash,
          decidedAt: record.decidedAt,
        },
      }),
    });
    if (!res.ok) {
      console.error(`approval.decided chain event refused for ${record.id}: ${res.status}`);
      return null;
    }
    return (await res.json()) as RecordResult;
  } catch (e) {
    console.error(
      `approval.decided chain event failed for ${record.id}: ${e instanceof Error ? e.message : e}`,
    );
    return null;
  }
}
