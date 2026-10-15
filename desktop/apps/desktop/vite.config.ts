import { defineConfig } from "vitest/config";

// Tauri expects a fixed dev port (devUrl in tauri.conf.json) and a relative base
// so that assets resolve from the bundled frontendDist.
export default defineConfig({
  base: "./",
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true, target: "es2022", sourcemap: false },
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.ts"],
    restoreMocks: true,
  },
});
