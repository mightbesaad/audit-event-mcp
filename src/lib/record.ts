import { AuditLog } from "@/lib/audit-log";
import type { AuditEventInput, AuditLogConfig, RecordResult } from "@/lib/types";

export async function record(
  config: AuditLogConfig,
  event: AuditEventInput,
): Promise<RecordResult> {
  return new AuditLog(config).record(event);
}
