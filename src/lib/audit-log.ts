import type { AuditEventInput, AuditLogConfig, RecordResult } from "@/lib/types";

export class AuditLog {
  private readonly config: AuditLogConfig;

  constructor(config: AuditLogConfig) {
    this.config = config;
  }

  async record(event: AuditEventInput): Promise<RecordResult> {
    const id = this.config.doNamespace.idFromName(`audit-do-${this.config.clientId}`);
    const stub = this.config.doNamespace.get(id);
    const response = await stub.fetch("https://do-internal/record", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...event, agentId: this.config.agentId }),
    });
    if (!response.ok) {
      throw new Error(`AuditLog.record failed: ${response.status}`);
    }
    return response.json<RecordResult>();
  }
}
