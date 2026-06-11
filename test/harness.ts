import type { DatabaseSync, SqliteValue } from "node:sqlite";
import type { Env } from "@/lib/types";

// --- SqlStorage adapter ---
// Wraps node:sqlite DatabaseSync to satisfy the SqlStorage interface used by AuditDO.
// Routing: multi-statement DDL → exec(); SELECT → prepare().all(); everything else → prepare().run().
export function makeSqlStorage(db: DatabaseSync) {
  return {
    exec<T>(sql: string, ...params: unknown[]) {
      const trimmed = sql.trimStart().toUpperCase();

      // Multi-statement SQL (e.g., SCHEMA_SQL with CREATE TABLE + CREATE INDEX × 3)
      if (trimmed.split(";").filter((s) => s.trim()).length > 1) {
        db.exec(sql);
        return { toArray: (): T[] => [] };
      }

      const stmt = db.prepare(sql);

      if (trimmed.startsWith("SELECT")) {
        const rows = params.length > 0 ? stmt.all(...(params as SqliteValue[])) : stmt.all();
        return { toArray: (): T[] => rows as unknown as T[] };
      }

      // INSERT / UPDATE / DELETE — run(), no rows returned
      if (params.length > 0) {
        stmt.run(...(params as SqliteValue[]));
      } else {
        stmt.run();
      }
      return { toArray: (): T[] => [] };
    },
  };
}

export function makeState(db: DatabaseSync): DurableObjectState {
  return {
    storage: {
      sql: makeSqlStorage(db),
      getAlarm: async () => null,
      setAlarm: async () => {},
    },
  } as unknown as DurableObjectState;
}

export function makeMockNotary(): Fetcher {
  return {
    async fetch(_req: RequestInfo, _init?: RequestInit) {
      return Response.json({
        merkleRoot: "a".repeat(64),
        notarySig: "b".repeat(128),
      });
    },
  } as unknown as Fetcher;
}

export function makeMockR2(): R2Bucket {
  const store = new Map<string, { body: string; customMetadata?: Record<string, string> }>();
  return {
    async put(
      key: string,
      value: unknown,
      options?: { httpMetadata?: unknown; customMetadata?: Record<string, string> },
    ) {
      store.set(key, { body: String(value), customMetadata: options?.customMetadata });
      return {} as R2Object;
    },
  } as unknown as R2Bucket;
}

export const fakeEnv = {} as unknown as Env;

export function post(path: string, body: unknown, headers?: Record<string, string>): Request {
  return new Request(`https://do-internal${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
