import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "playwright-report" }],
  ],
  projects: [
    {
      name: "production",
      testIgnore: [
        "fleet-group-authorization.spec.ts",
        "fleet-fixture-runs.spec.ts",
        "fleet-native-assessment.spec.ts",
        "fleet-native-capacity.spec.ts",
        "fleet-joint-decision.spec.ts",
        "commitment-portfolio.spec.ts",
        "commitment-decision.spec.ts",
      ],
      use: { baseURL: process.env.FINOPS_WEB_URL || "http://localhost:3000" },
    },
    {
      name: "isolated-presentation",
      testMatch: [
        "fleet-group-authorization.spec.ts",
        "fleet-fixture-runs.spec.ts",
        "fleet-native-assessment.spec.ts",
        "fleet-native-capacity.spec.ts",
        "fleet-joint-decision.spec.ts",
        "commitment-portfolio.spec.ts",
        "commitment-decision.spec.ts",
      ],
      use: { baseURL: "http://127.0.0.1:4177" },
    },
  ],
  webServer: {
    name: "isolated-presentation",
    command: "node tests/presentation-server.mjs",
    url: "http://127.0.0.1:4177/__presentation_health",
    reuseExistingServer: false,
    timeout: 30_000,
    gracefulShutdown: { signal: "SIGTERM", timeout: 5_000 },
  },
  use: {
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    viewport: { width: 1440, height: 1000 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
});
