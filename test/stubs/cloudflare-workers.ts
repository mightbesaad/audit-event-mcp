// Minimal Node-side stand-in for the `cloudflare:workers` runtime module, aliased in
// vitest.config.ts. Only what src/main.ts touches: a WorkerEntrypoint base exposing ctx/env.
export class WorkerEntrypoint<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;

  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
