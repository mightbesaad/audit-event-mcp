import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      // Runtime-only module; stubbed so src/main.ts (entrypoint wiring) is testable in Node.
      "cloudflare:workers": path.resolve(__dirname, "test/stubs/cloudflare-workers.ts"),
    },
  },
  test: {
    environment: "node",
    server: {
      deps: {
        // Force the library through Vite's resolver so the cloudflare:workers alias above
        // applies to it too — Node's native ESM loader cannot load the cloudflare: scheme.
        inline: ["@cloudflare/workers-oauth-provider"],
      },
    },
  },
});
