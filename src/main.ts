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
import type { Env } from "@/lib/types";

export { AuditDO } from "@/do";

// Deploy entry for the gated worker. It exists as a separate module (rather than living in
// index.ts) because `cloudflare:workers` cannot be imported in the Node test environment, and
// the whole HTTP test suite imports index.ts directly. Public HTTP behavior is unchanged:
// the default export below is exactly the Hono app from index.ts.
export default worker;

// Module-scope rather than a class method: Workers RPC exposes prototype methods to the binding
// peer regardless of TypeScript visibility, and a helper that turns a clientId into a full DO
// stub must never be part of the callable surface — the contract is get/decide only.
function stubFor(env: Env, clientId: string): DurableObjectStub {
  const doId = env.AUDIT_DO.idFromName(`audit-do-${clientId}`);
  return env.AUDIT_DO.get(doId);
}

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
    const res = await stubFor(this.env, clientId).fetch("https://do-internal/approval/get", {
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
    const res = await stubFor(this.env, params.clientId).fetch(
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
    return (await res.json()) as DecideResult;
  }
}
