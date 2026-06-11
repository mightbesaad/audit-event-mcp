import type { ApprovalCreateResult } from "@/lib/approval";
import { isValidClientIdShape } from "@/lib/approval";
import type { Env, RecordResult } from "@/lib/types";

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

  return {
    status: 200,
    body: {
      approvalId: created.approvalId,
      status: record.status,
      expiresAt: created.expiresAt,
      actionPayloadHash: record.actionPayloadHash,
      chainEvent,
    },
  };
}
