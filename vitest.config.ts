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
  },
});
