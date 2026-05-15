import type { MiddlewareHandler } from "hono";
import type { AuditLogConfig } from "@/lib/types";

// TODO(M8-next): auto-record human.turn on request, tool.call + tool.result on MCP tool dispatch
export function auditMiddleware(_config: AuditLogConfig): MiddlewareHandler {
  return async (_c, next) => {
    await next();
  };
}
