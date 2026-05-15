import { z } from "zod";

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
