// Type declarations for node:sqlite (not included in @cloudflare/workers-types).
// Node.js 22.5+ ships sqlite as a stable built-in. These types cover the subset used in tests.

declare module "node:sqlite" {
  type SqliteValue = string | number | bigint | ArrayBuffer | null;

  interface StatementResultingChanges {
    changes: number;
    lastInsertRowid: number | bigint;
  }

  interface StatementSync {
    run(...params: SqliteValue[]): StatementResultingChanges;
    get(...params: SqliteValue[]): Record<string, SqliteValue> | undefined;
    all(...params: SqliteValue[]): Record<string, SqliteValue>[];
    expandedSQL?: string;
    sourceSQL?: string;
  }

  interface DatabaseSyncOptions {
    open?: boolean;
    readOnly?: boolean;
    allowExtension?: boolean;
  }

  class DatabaseSync {
    constructor(location: string, options?: DatabaseSyncOptions);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
