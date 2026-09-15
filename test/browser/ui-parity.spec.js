const path = require("node:path");
const { test, expect } = require("@playwright/test");

async function liveConnected(page) {
  await expect(page.locator("[data-phx-main]")).toHaveClass(/\bphx-connected\b/);
}

async function openSession(page) {
  await page.goto("/auth");
  await page.getByLabel("Access token").fill("ouroboros-browser-test-token-000000000000");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/$/);
  await page.goto("/new");
  await liveConnected(page);
  await page.locator("#workspace").fill(path.resolve(__dirname, "../../_build/playwright-workspace"));
  await page.getByRole("button", { name: "Start session", exact: true }).click();
  await expect(page).toHaveURL(/\/s\/interactive\//);
  await liveConnected(page);
}

async function sendTurn(page) {
  await page.locator("#ouro-composer-input").fill("browser stream");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.locator("#transcript")).toContainText("Streaming proof complete.");
  await expect(page.locator("[data-ouro-interrupt]")).toHaveCount(0);
  await expect(page.locator("#ouro-composer-input")).toHaveValue("");
}

async function openPalette(page) {
  await page.getByRole("button", { name: /Commands/ }).click();
  await expect(page.locator("#ouro-palette")).toBeVisible();
  await expect(page.locator("#ouro-palette-list [role=option]").first()).toBeVisible();
}

test("backtrack replaces and persists the browser draft without sending it", async ({ page }) => {
  await openSession(page);
  await sendTurn(page);
  const composer = page.locator("#ouro-composer-input");
  const transcriptBefore = await page.locator("#transcript").innerText();

  // Empty, different, and identical local drafts all take the chosen message. The last
  // case used to treat the replacement as a send acknowledgement and clear it instead.
  for (const previous of ["", "an unsent draft", "browser stream"]) {
    await composer.fill(previous);
    await openPalette(page);
    await page.locator('[phx-value-id="conversation.backtrack"]').click();
    await page.locator('[phx-click="w3-backtrack-edit"]').first().click();
    await expect(page.locator("#ouro-backtrack")).toHaveCount(0);
    await expect(composer).toHaveValue("browser stream");
    await expect(composer).toBeFocused();
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled();
    expect(await page.locator("#transcript").innerText()).toBe(transcriptBefore);
    const draftKey = await composer.getAttribute("data-draft-key");
    expect(await page.evaluate(key => sessionStorage.getItem("ouroboros.draft." + key), draftKey))
      .toBe("browser stream");
  }

  await page.reload();
  await liveConnected(page);
  await expect(composer).toHaveValue("browser stream");
  await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled();
});

test("palette keyboard selection stays visible while the search box keeps focus", async ({ page }) => {
  await openSession(page);
  await openPalette(page);
  const list = page.locator("#ouro-palette-list");
  const rows = list.getByRole("option");
  const query = page.getByRole("combobox", { name: "Search commands" });
  const count = await rows.count();
  expect(count).toBeGreaterThan(10);

  for (let index = 1; index < count; index++) {
    await query.press("ArrowDown");
    await expect(rows.nth(index)).toHaveAttribute("aria-selected", "true");
  }
  await expect(rows.last()).toBeInViewport();
  await expect(query).toBeFocused();
  await expect(query).toHaveAttribute("aria-activedescendant", await rows.last().getAttribute("id"));
  expect(await list.evaluate(el => el.scrollTop)).toBeGreaterThan(0);

  for (let index = count - 2; index >= 0; index--) {
    await query.press("ArrowUp");
    await expect(rows.nth(index)).toHaveAttribute("aria-selected", "true");
  }
  await expect(rows.first()).toBeInViewport();
  await expect(query).toBeFocused();

  await query.fill("Keyboard shortcuts");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toBeInViewport();
  await expect(query).toHaveAttribute("aria-activedescendant", await rows.first().getAttribute("id"));
  await query.press("Enter");
  await expect(page.locator("#ouro-shortcuts")).toBeVisible();
});

test("copy controls stay visible on touch screens and respect reduced motion", async ({ page }) => {
  await openSession(page);
  await sendTurn(page);
  const actions = page.locator(".ouro-cell-actions").first();
  await page.mouse.move(0, 0);
  await page.locator("#ouro-composer-input").focus();

  // Exercise both media conditions independently in each browser project.
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(actions).toHaveCSS("opacity", "1");
  await openPalette(page);
  await expect.poll(() => page.locator("#ouro-palette").evaluate(el =>
    parseFloat(getComputedStyle(el).maxHeight) / window.innerHeight)).toBeGreaterThan(0.8);
  await page.locator("#ouro-palette-query").press("Escape");
  await expect(page.locator("#ouro-palette")).toHaveCount(0);

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(actions).toHaveCSS("opacity", "1");
  await expect(actions).toHaveCSS("transition-duration", "0s");
});
