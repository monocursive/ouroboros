const { test, expect } = require("@playwright/test");
const path = require("node:path");
const fs = require("node:fs");
const token = "ouroboros-browser-test-token-000000000000";
const model = "openai_codex:fixture-astra";
const connected = page => expect(page.locator("[data-phx-main]")).toHaveClass(/\bphx-connected\b/);

test("launch project and missing-catalogue model survive into a native request", async ({ page }, info) => {
  const root = path.resolve(__dirname, "../../_build/playwright-workspace");
  const project = fs.mkdtempSync(path.join(root, `first-use-${info.project.name}-`));
  const workspace = path.join(project, "repo + & % # é ");
  fs.mkdirSync(workspace);
  try {
    // The URL is the Rust CLI's auth-query contract. Server cwd is the source tree,
    // deliberately not this invocation's project. No installed CLI is exercised here.
    await page.goto(`/auth?${new URLSearchParams({ token, workspace })}`);
    await expect(page).toHaveURL(/\/new\?workspace=/);
    expect(page.url()).not.toContain(token);
    await connected(page);
    await expect(page.locator("#workspace")).toHaveValue(workspace);
    await page.locator("details.ouro-new-advanced summary").click();
    await page.getByRole("searchbox", { name: "search models", exact: true }).fill("astra");
    const models = page.locator("select[name=model_choice]");
    await expect(models.locator(`option[value="catalog:${model}"]`)).toHaveCount(1);
    await models.selectOption(`catalog:${model}`);
    await page.locator("select[name=effort]").selectOption("xhigh");
    await expect(page.getByText("Using " + model, { exact: true })).toBeVisible();
    await page.locator("#initial-message").fill("first-use request proof");
    await page.getByRole("button", { name: "Start session", exact: true }).click();
    await expect(page).toHaveURL(/\/s\/interactive\//);
    await connected(page);
    await expect(page.getByRole("log", { name: "Session transcript" })).toContainText(`Requested model=${model}; reasoning=xhigh`);
    // Successful start persists the exact explicit path/model/thinking, even without
    // a CLI link on the next visit. Spaces in a directory name remain significant.
    await page.goto("/new");
    await connected(page);
    await expect(page.locator("#workspace")).toHaveValue(workspace);
    await expect(models).toHaveValue(`catalog:${model}`);
    await expect(page.locator("select[name=effort]")).toHaveValue("xhigh");
    // A second invocation attaches to the same fixture but supplies a different cwd.
    await page.goto(`/auth?${new URLSearchParams({ token, workspace: project })}`);
    await connected(page);
    await expect(page.locator("#workspace")).toHaveValue(project);
    await page.locator("#workspace").fill(workspace);
    await expect(page.locator("#workspace")).toHaveValue(workspace);
    // The Custom route must send a different, exact absent ID, not the configured
    // recommendation. It must survive search, request construction, and preferences.
    const exact = "openai_codex:fixture-astra-exact";
    await page.locator("details.ouro-new-advanced summary").click();
    await models.selectOption("custom");
    await page.getByRole("textbox", { name: "custom model id", exact: true }).fill(exact);
    await page.locator("select[name=effort]").selectOption("xhigh");
    await expect(page.getByText("Using " + exact, { exact: true })).toBeVisible();
    await page.locator("#initial-message").fill("first-use request proof");
    await page.getByRole("button", { name: "Start session", exact: true }).click();
    await expect(page).toHaveURL(/\/s\/interactive\//);
    await connected(page);
    await expect(page.getByRole("log", { name: "Session transcript" })).toContainText(`Requested model=${exact}; reasoning=xhigh`);
    await page.goto("/new");
    await connected(page);
    await expect(page.locator("#workspace")).toHaveValue(workspace);
    await expect(models).toHaveValue(`catalog:${exact}`);
    await expect(page.locator("select[name=effort]")).toHaveValue("xhigh");
    await page.goto("/new?workspace=relative");
    await connected(page);
    await expect(page.locator("#workspace")).toHaveValue("");
    await expect(page.getByRole("button", { name: "Start session", exact: true })).toBeDisabled();

    // A real loop stream-consumption failure, projected into the ordinary browser cell.
    await page.goto(`/auth?${new URLSearchParams({ token, workspace })}`);
    await connected(page);
    await page.locator("#initial-message").fill("browser private failure");
    await page.getByRole("button", { name: "Start session", exact: true }).click();
    await expect(page).toHaveURL(/\/s\/interactive\//);
    const transcript = page.getByRole("log", { name: "Session transcript" });
    await expect(transcript).toContainText("The AI service limited the request.");
    await expect(transcript).toContainText("marked retryable");
    await transcript.locator(".ouro-technical summary").click();
    await expect(transcript.locator(".ouro-technical pre")).toContainText("status=429");
    await expect(transcript).not.toContainText("SYNTH_BROWSER_SECRET");
  } finally {
    fs.rmSync(project, { recursive: true });
  }
});