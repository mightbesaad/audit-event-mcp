export const MCP_TOOL_DEFINITIONS = [
  {
    name: "record_event",
    description:
      "Write one audit event to the hash-chained log. Returns the event id and chain_hash.",
    inputSchema: {
      type: "object",
      required: ["agentId", "eventType", "purpose", "sessionId"],
      properties: {
        agentId: { type: "string", minLength: 1 },
        eventType: {
          type: "string",
          enum: [
            "tool.call",
            "tool.result",
            "decision.made",
            "human.turn",
            "memory.read",
            "memory.write",
            "error.raised",
          ],
        },
        purpose: { type: "string", minLength: 1, maxLength: 200 },
        sessionId: { type: "string" },
        input: { description: "Raw input — library hashes it; never stored unless r2Bucket bound" },
        inputHashOmittedReason: {
          type: "string",
          description:
            "Required when input is omitted. e.g. 'no_personal_data' | 'caller_opted_out'",
        },
        lawfulBasis: {
          type: "string",
          enum: [
            "legitimate_interest",
            "contract",
            "legal_obligation",
            "vital_interest",
            "public_task",
            "consent",
          ],
        },
        subjectId: { type: "string" },
        retentionDays: { type: "integer", minimum: 1 },
      },
    },
  },
  {
    name: "verify_chain",
    description:
      "Recompute chain_hash for a range of events and report any breaks. Returns verified count and broken entries.",
    inputSchema: {
      type: "object",
      properties: {
        fromId: { type: "string", description: "Start from this event id (inclusive)" },
        limit: { type: "integer", minimum: 1, maximum: 1000, default: 100 },
      },
    },
  },
  {
    name: "query_events",
    description:
      "Filter events by session_id, event_type, agent_id, or date range. Returns paginated events. input_hash is never returned.",
    inputSchema: {
      type: "object",
      properties: {
        sessionId: { type: "string" },
        eventType: { type: "string" },
        agentId: { type: "string" },
        fromDate: { type: "string", description: "ISO-8601 UTC" },
        toDate: { type: "string", description: "ISO-8601 UTC" },
        limit: { type: "integer", minimum: 1, maximum: 500, default: 50 },
        cursor: { type: "string" },
      },
    },
  },
  {
    name: "export_dossier",
    description:
      "Export all events for a subject_id as a signed JSON-L file (GDPR Art. 20 portability). Returns an R2 presigned URL valid for 1 hour.",
    inputSchema: {
      type: "object",
      required: ["subjectId"],
      properties: {
        subjectId: { type: "string" },
      },
    },
  },
  {
    name: "request_approval",
    description:
      "Ask a human to approve an action before it runs. Creates a pending approval, witnesses it as an approval.requested chain event, and returns approvalId, approvalUrl (one-tap approve page), and webhookSecret. Outcomes are approved | denied | timeout — poll with check_approval, or receive the signed decision webhook at callbackUrl.",
    inputSchema: {
      type: "object",
      required: ["agentId", "sessionId", "actionSummary"],
      properties: {
        agentId: { type: "string", minLength: 1, maxLength: 128 },
        sessionId: {
          type: "string",
          description: "Same session id as the rest of this agent's recorded evidence",
        },
        actionSummary: {
          type: "string",
          minLength: 1,
          maxLength: 280,
          description: "Human-oriented description, shown verbatim to the approver",
        },
        actionPayload: {
          type: "object",
          required: ["tool"],
          additionalProperties: false,
          properties: {
            tool: { type: "string", minLength: 1, maxLength: 128 },
            args: { description: "The exact arguments the tool will run with" },
          },
          description:
            "The structured action about to run. Hashed server-side into the chain so the summary shown to the human and the action itself can never drift apart.",
        },
        ttlSeconds: {
          type: "integer",
          minimum: 1,
          maximum: 604800,
          description: "Defaults: 30 min; 4 h when channels is exactly ['email']",
        },
        channels: {
          type: "array",
          maxItems: 4,
          items: { type: "string", enum: ["telegram", "push", "email"] },
        },
        callbackUrl: {
          type: "string",
          description: "https URL that receives the signed approval.decided webhook",
        },
      },
    },
  },
  {
    name: "check_approval",
    description:
      "Poll an approval's status. Returns pending | approved | denied | timeout, with reason and responder once decided.",
    inputSchema: {
      type: "object",
      required: ["approvalId"],
      properties: {
        approvalId: { type: "string", minLength: 1, maxLength: 64 },
      },
    },
  },
] as const;
