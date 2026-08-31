const path = require("node:path");
const { defineConfig, devices } = require("@playwright/test");

const port = 4057;
const token = "ouroboros-browser-test-token-000000000000";

module.exports = defineConfig({
  testDir: "./test/browser",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    channel: process.platform === "darwin" ? "chrome" : "chromium",
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  projects: [
    { name: "desktop-chromium", use: { ...devices["Desktop Chrome"] } },
    {
      name: "mobile-chromium",
      use: { ...devices["iPhone 13"], defaultBrowserType: "chromium" }
    }
  ],
  webServer: {
    command: "mix run --no-halt",
    url: `http://127.0.0.1:${port}/auth`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      ...process.env,
      MIX_ENV: "test",
      OUROBOROS_DATA_DIR: path.join(__dirname, "_build", "playwright-data"),
      OUROBOROS_WEB: "1",
      OUROBOROS_WEB_BIND: "127.0.0.1",
      OUROBOROS_WEB_PORT: String(port),
      OUROBOROS_WEB_SCOPE: "operate",
      OUROBOROS_WEB_TOKEN: token
    }
  }
});
