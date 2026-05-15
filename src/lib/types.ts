export type EventType =
  | "tool.call"
  | "tool.result"
  | "decision.made"
  | "human.turn"
  | "memory.read"
  | "memory.write"
  | "error.raised";

export type LawfulBasis =
  | "legitimate_interest"
  | "contract"
  | "legal_obligation"
  | "vital_interest"
  | "public_task"
  | "consent";

export interface AuditLogConfig {
  agentId: string;
  doNamespace: DurableObjectNamespace;
  clientId: string;
  r2Bucket?: R2Bucket;
  defaultLawfulBasis?: LawfulBasis;
  defaultRetentionDays?: number;
}

export interface AuditEventInput {
  eventType: EventType;
  purpose: string;
  sessionId: string;
  input?: unknown;
  inputHashOmittedReason?: string;
  lawfulBasis?: LawfulBasis;
  subjectId?: string;
  retentionDays?: number;
  stripeCardId?: string;
  stripeAuthorizationId?: string;
}

export interface AuditEvent {
  id: string;
  agentId: string;
  sessionId: string;
  eventType: EventType;
  inputHash: string | null;
  inputHashOmittedReason: string | null;
  payloadRef: string | null;
  lawfulBasis: LawfulBasis | null;
  purpose: string;
  subjectId: string | null;
  retentionDays: number;
  prevHash: string | null;
  chainHash: string;
  merkleRoot: string | null;
  notarySig: string | null;
  stripeCardId: string | null;
  stripeAuthorizationId: string | null;
  createdAt: string;
}

export interface RecordResult {
  id: string;
  chainHash: string;
}

export interface VerifyResult {
  verified: number;
  broken: { id: string; expected: string; actual: string }[];
}

export interface DossierResult {
  url: string;
  expiresAt: string;
  eventCount: number;
}

export interface Env {
  AUDIT_DO: DurableObjectNamespace;
  AUDIT_PAYLOADS?: R2Bucket;
  NOTARY?: Fetcher;
}
