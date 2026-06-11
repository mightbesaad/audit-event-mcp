import { z } from "zod";
import {
  MAX_ACTION_SUMMARY_CHARS,
  MAX_AGENT_ID_CHARS,
  MAX_APPROVAL_ID_CHARS,
  MAX_APPROVAL_TTL_SECONDS,
  MAX_REASON_CHARS,
  MIN_APPROVAL_TTL_SECONDS,
} from "@/lib/approval";

const EVENT_TYPES = [
  "tool.call",
  "tool.result",
  "decision.made",
  "human.turn",
  "memory.read",
  "memory.write",
  "error.raised",
] as const;

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

export const ApprovalCreateRequestSchema = z.object({
  agentId: z.string().min(1).max(MAX_AGENT_ID_CHARS),
  actionSummary: z.string().min(1).max(MAX_ACTION_SUMMARY_CHARS),
  // SHA-256 hex of the structured action payload (D6); hashing pipeline arrives with chain events
  actionPayloadHash: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
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
