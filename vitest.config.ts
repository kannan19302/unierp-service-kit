import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "src/**/*.spec.ts", "*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      reportsDirectory: "./coverage",
      // J02 — `all: true` so coverage counts untested source files and can
      // fail. Floor is 0: src/ has no real tests yet (placeholder only), so
      // 0 is the truthful floor and the ratchet may only rise.
      all: true,
      include: ["src/**"],
      thresholds: {
        lines: 0,
        functions: 0,
        branches: 0,
        statements: 0,
      },
      exclude: [
        "src/**/*.test.ts",
        "src/**/*.spec.ts",
        "src/**/__tests__/**",
        "src/index.ts",
      ],
    },
  },
});
