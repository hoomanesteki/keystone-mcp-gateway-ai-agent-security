import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The realm's `console` client allows http://localhost:5173/* and nothing else, so the port is
// fixed: a dev server that quietly moved to 5174 would sign in to an error page.
const KEYSTONE = process.env["KEYSTONE_URL"] ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    // The admin API is served from the page's own origin, so the browser makes no cross-origin
    // request and the API's CORS rule never comes into it.
    proxy: { "/admin": { target: KEYSTONE, changeOrigin: true } },
  },
  preview: {
    port: 5173,
    strictPort: true,
    proxy: { "/admin": { target: KEYSTONE, changeOrigin: true } },
  },
  build: { sourcemap: true },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    css: false,
  },
});
