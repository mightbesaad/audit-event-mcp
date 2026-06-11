import { WorkerEntrypoint } from "cloudflare:workers";
import worker from "@/index";
import {
  type ApprovalDecision,
  type ApprovalInternalClient,
  type ApprovalRecord,
  type DecideResult,
  isValidApprovalIdShape,
  isValidClientIdShape,
} from "@/lib/approval";
import { tenantStub, witnessDecision } from "@/lib/approval-flow";
import type { Env } from "@/lib/types";
import { sendDecisionWebhook } from "@/lib/webhook";

export { AuditDO } from "@/do";

// Deploy entry for the gated worker. It exists as a separate module (rather than living in
// index.ts) because `cloudflare:workers` cannot be imported in the Node test environment, and
// the whole HTTP test suite imports index.ts directly. Public HTTP behavior is unchanged:
// the default export below is exactly the Hono app from index.ts.
export default worker;

// DO-stub derivation stays off this class: Workers RPC exposes prototype methods to the
// binding peer regardless of TypeScript visibility, and a helper that turns a clientId into
// a full DO stub must never be part of the callable surface — the contract is get/decide
// only. The shared definition lives in lib/approval-flow.ts (tenantStub).

// Internal surface for go.kajaril.com ONLY (decision D1). A named WorkerEntrypoint is reachable
// exclusively over a service binding that names it — it has no HTTP route, so the public worker's
// route table gains nothing and the everything-behind-Access invariant holds. The public worker
// passes a clientId it extracted from an HMAC-verified link token; the DO name is derived here,
// never from anything a browser sent.
export class ApprovalInternal extends WorkerEntrypoint<Env> implements ApprovalInternalClient {
  async getApproval(clientId: string, approvalId: string): Promise<ApprovalRecord | null> {
    // Shape checks are defense-in-depth: callers are trusted workers, but a malformed
    // clientId must never become a DO name.
    if (!isValidClientIdShape(clientId) || !isValidApprovalIdShape(approvalId)) return null;
    const res = await tenantStub(this.env, clientId).fetch("https://do-internal/approval/get", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approvalId }),
    });
    if (!res.ok) return null;
    return (await res.json()) as ApprovalRecord;
  }

  async decideApproval(params: {
    clientId: string;
    approvalId: string;
    decision: ApprovalDecision;
    reason?: string;
    responderId?: string;
  }): Promise<DecideResult> {
    if (!isValidClientIdShape(params.clientId) || !isValidApprovalIdShape(params.approvalId)) {
      return { ok: false, reason: "not_found" };
    }
    const res = await tenantStub(this.env, params.clientId).fetch(
      "https://do-internal/approval/decide",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          approvalId: params.approvalId,
          decision: params.decision,
          reason: params.reason,
          responderId: params.responderId,
        }),
      },
    );
    // The DO encodes every outcome (ok / not_found / already_decided / expired) in the
    // DecideResult body; HTTP status is transport detail here. A 400 means the body is a
    // validation error, not a DecideResult — collapse it to not_found.
    if (res.status === 400) return { ok: false, reason: "not_found" };
    const result = (await res.json()) as DecideResult;

    if (result.ok && result.record) {
      const record = result.record;
      // Witnessed synchronously — the chain event is the evidence; the webhook below is
      // only the resume accelerator and runs after the response via waitUntil (D4/D7).
      const chainEvent = await witnessDecision(this.env, params.clientId, record);

      if (record.callbackUrl) {
        if (this.env.WEBHOOK_SIGNING_SECRET) {
          this.ctx.waitUntil(
            sendDecisionWebhook({
              master: this.env.WEBHOOK_SIGNING_SECRET,
              clientId: params.clientId,
              callbackUrl: record.callbackUrl,
              body: {
                type: "approval.decided",
                approval: {
                  id: record.id,
                  agentId: record.agentId,
                  sessionId: record.sessionId,
                  status: record.status as "approved" | "denied",
                  reason: record.reason,
                  responderId: record.responderId,
                  actionSummary: record.actionSummary,
                  actionPayloadHash: record.actionPayloadHash,
                  createdAt: record.createdAt,
                  decidedAt: record.decidedAt,
                  expiresAt: record.expiresAt,
                },
                chainEvent,
              },
            }),
          );
        } else {
          // Fail closed (D9): an unsigned webhook is forgeable, so none is sent. Polling
          // still resolves the approval; this log is the operator's cue to bind the secret.
          console.error("decision webhook skipped: WEBHOOK_SIGNING_SECRET unset");
        }
      }
    }
    return result;
  }
}
