import { defineConfig, devices } from "@playwright/test";
import { devEnv, urls } from "./e2e/support/dev-env";

const env = devEnv();

// Chromium only, headless. The whole run, from the stack check to the last assertion, takes under
// 90 seconds: Keystone holds the transfer for 10 seconds (deploy/keystone.compose.yaml) and the
// rest is a sign-in and a click.
export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  // One test, one stack and one bank: nothing here can run beside another test.
  workers: 1,
  fullyParallel: false,
  // A retry would approve a second request against a bank that already has the transfer.
  retries: 0,
  timeout: 75_000,
  expect: { timeout: 15_000 },
  reporter: process.env["CI"] ? [["github"], ["list"]] : [["list"]],
  use: {
    baseURL: "http://localhost:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "pnpm dev",
    url: "http://localhost:5173",
    // A developer's own `pnpm dev` is used as it is. CI starts its own.
    reuseExistingServer: !process.env["CI"],
    timeout: 30_000,
    env: {
      KEYSTONE_URL: urls(env).keystone,
      VITE_OIDC_AUTHORITY: urls(env).realm,
    },
  },
});
