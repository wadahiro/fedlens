import { defineConfig, devices } from "@playwright/test";

const captureMode = process.env.CAPTURE === "1";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: 1,
  workers: 1,
  reporter: "html",
  use: {
    baseURL: "http://oidc.example.com:3000",
    proxy: {
      server: "socks5://localhost:1080",
    },
    trace: captureMode ? "on" : "retain-on-failure",
    video: captureMode ? "on" : "retain-on-failure",
    screenshot: captureMode ? "on" : "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
});
