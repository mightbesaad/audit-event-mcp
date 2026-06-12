import { z } from "zod";
import {
  MAX_ACTION_SUMMARY_CHARS,
  MAX_ACTION_TOOL_CHARS,
  MAX_AGENT_ID_CHARS,
  MAX_APPROVAL_ID_CHARS,
  MAX_APPROVAL_TTL_SECONDS,
  MAX_REASON_CHARS,
  MIN_APPROVAL_TTL_SECONDS,
} from "@/lib/approval";

// approval.* types are additive (decision D7) and emitted ONLY by the worker layer
// (approval-flow / ApprovalInternal) — the public record_event surface rejects them so an
// agent can never fabricate human-decision evidence (guard in index.ts).
// Reserved for v1.5, do not repurpose: "approval.deferred", "approval.escalated".
const EVENT_TYPES = [
  "tool.call",
  "tool.result",
  "decision.made",
  "human.turn",
  "memory.read",
  "memory.write",
  "error.raised",
  "approval.requested",
  "approval.decided",
] as const;

export const RESERVED_EVENT_TYPE_PREFIX = "approval.";

const LAWFUL_BASES = [
  "legitimate_interest",
  "contract",
  "legal_obligation",
  "vital_interest",
  "public_task",
  "consent",
] as const;

export const EventTypeSchema = z.enum(EVENT_TYPES);
export const LawfulBasisSchema = z.enum(LAWFUL_BASES);

export const AuditEventInputSchema = z
  .object({
    eventType: EventTypeSchema,
    purpose: z.string().min(1).max(200),
    sessionId: z.string().min(1),
    input: z.unknown().optional(),
    inputHashOmittedReason: z.string().min(1).optional(),
    lawfulBasis: LawfulBasisSchema.optional(),
    subjectId: z.string().optional(),
    retentionDays: z.number().int().positive().optional(),
    stripeCardId: z.string().optional(),
    stripeAuthorizationId: z.string().optional(),
  })
  .refine(
    (data) => {
      const hasInput = data.input !== undefined;
      const hasReason = data.inputHashOmittedReason !== undefined;
      return hasInput !== hasReason;
    },
    { message: "Exactly one of input or inputHashOmittedReason must be provided" },
  );

export const DoRecordRequestSchema = AuditEventInputSchema.and(
  z.object({ agentId: z.string().min(1) }),
);

export type DoRecordRequest = z.infer<typeof DoRecordRequestSchema>;

// --- approvals (decision D3) ---

// telegram/push delivery lands with the channel ladder (D4); the enum is fixed now so
// stored channel lists never need migrating. Empty array is valid — self-hosters without
// a configured channel still get an approval_url back.
const APPROVAL_CHANNELS = ["telegram", "push", "email"] as const;

// Structured action payload (decision D6). Strict: the witnessed artifact is exactly
// {tool, args} — extra keys would be hashed but never rendered to the human.
export const ActionPayloadSchema = z.strictObject({
  tool: z.string().min(1).max(MAX_ACTION_TOOL_CHARS),
  args: z.unknown().optional(),
});

export const ApprovalCreateRequestSchema = z.object({
  agentId: z.string().min(1).max(MAX_AGENT_ID_CHARS),
  // same shape rule as record_event's sessionId — approval chain events land in this session
  sessionId: z.string().min(1),
  actionSummary: z.string().min(1).max(MAX_ACTION_SUMMARY_CHARS),
  // The hash is always computed server-side from this payload (D6) — callers never supply
  // a hash directly, so the witnessed hash is honest relative to what the human is shown.
  actionPayload: ActionPayloadSchema.optional(),
  ttlSeconds: z
    .number()
    .int()
    .min(MIN_APPROVAL_TTL_SECONDS)
    .max(MAX_APPROVAL_TTL_SECONDS)
    .optional(),
  channels: z.array(z.enum(APPROVAL_CHANNELS)).max(4).optional(),
  // https only: the decision webhook (D4) posts approval outcomes here — never over cleartext
  callbackUrl: z
    .url({ protocol: /^https$/ })
    .max(2048)
    .optional(),
});

export const ApprovalDecideRequestSchema = z.object({
  approvalId: z.string().min(1).max(MAX_APPROVAL_ID_CHARS),
  decision: z.enum(["approved", "denied"]),
  reason: z.string().min(1).max(MAX_REASON_CHARS).optional(),
  responderId: z.string().min(1).max(256).optional(),
});

export type ApprovalCreateRequest = z.infer<typeof ApprovalCreateRequestSchema>;
export type ApprovalDecideRequest = z.infer<typeof ApprovalDecideRequestSchema>;
