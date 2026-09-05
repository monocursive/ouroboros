const { test, expect } = require("@playwright/test");

const authToken = "ouroboros-browser-test-token-000000000000";

async function expectMinimumTarget(locator) {
  await expect(locator).toBeVisible();
  const box = await locator.boundingBox();
  expect(box).not.toBeNull();
  expect(box.width).toBeGreaterThanOrEqual(44);
  expect(box.height).toBeGreaterThanOrEqual(44);
}

async function signIn(page) {
  await page.goto("/");

  const gate = page.getByRole("heading", { name: "Open Ouroboros" });

  if (await gate.isVisible()) {
    await page.getByLabel("Access token").fill(authToken);
    await expectMinimumTarget(page.getByLabel("Access token"));
    await expectMinimumTarget(page.getByRole("button", { name: "Continue" }));
    await page.getByRole("button", { name: "Continue" }).click();
  }

  await expect(page).toHaveURL(/\/$/);
  await expect(page).toHaveTitle("Sessions · Ouroboros");
}

test("sign-in recovery and progressive session setup", async ({ page }) => {
  await signIn(page);
  await expect(page.getByRole("link", { name: /Machines/ })).toBeVisible();
  await page.getByRole("link", { name: /Machines/ }).click();
  await expect(page).toHaveTitle("Advanced · Machines · Ouroboros");
  await page.getByRole("link", { name: "Sessions", exact: true }).click();

  await page.getByRole("link", { name: "New session", exact: true }).click();
  await expect(page).toHaveTitle("New session · Ouroboros");
  await expect(page.locator("#workspace")).toBeVisible();
  await expect(page.locator("#initial-message")).toBeVisible();
  await expectMinimumTarget(page.locator("#workspace"));
  await expectMinimumTarget(page.locator("#initial-message"));

  const advanced = page.locator("details.ouro-new-advanced");
  const provider = page.locator("#provider");
  await expect(advanced).not.toHaveAttribute("open", "");
  await expect(provider).not.toBeVisible();

  await advanced.locator("summary").click();
  await expect(provider).toBeEnabled();
  await expect(provider).not.toHaveValue("");
  await expectMinimumTarget(provider);
  await expectMinimumTarget(page.getByRole("button", { name: "Start session" }));
  await expect(provider.locator("option:checked")).toBeEnabled();
});

test("session controls stay reachable and dialogs are modal", async ({ page }, testInfo) => {
  await signIn(page);
  await page.getByRole("link", { name: "New session", exact: true }).click();

  const provider = page.locator("#provider");
  await expect(provider).toBeEnabled();
  await expect(provider).not.toHaveValue("");

  const start = page.getByRole("button", { name: "Start session" });
  await expect(start).toBeEnabled();
  await start.click();
  await expect(page).toHaveURL(/\/s\/interactive\//);

  const composer = page.locator("#ouro-composer-input");
  await expect(composer).toBeVisible();
  const send = page.getByRole("button", { name: "Send" });
  await expect(send).toBeDisabled();
  await expectMinimumTarget(composer);
  await expectMinimumTarget(send);

  if (testInfo.project.name === "mobile-chromium") {
    const box = await composer.boundingBox();
    expect(box).not.toBeNull();
    expect(box.y).toBeLessThan(page.viewportSize().height);
    await expect(page.getByText("Session details", { exact: true })).toBeVisible();
  }

  const sessions = page.getByRole("button", { name: "← Sessions", exact: true });
  if (await sessions.isVisible()) await sessions.click();
  const row = page.locator(".ouro-row-wrap").filter({
    has: page.locator('a[aria-current="page"]')
  });
  const actions = row.locator(".ouro-row-actions > summary");
  await expectMinimumTarget(actions);
  await actions.click();
  const end = row.getByRole("button", { name: /^End / });
  await expect(end).toBeVisible();
  await expectMinimumTarget(end);
  await end.click();

  const dialog = page.getByRole("dialog", { name: "End session" });
  await expect(dialog).toBeVisible();
  expect(await dialog.evaluate((element) => element.matches(":modal"))).toBe(true);
  expect(await page.evaluate(() => document.activeElement.closest("dialog") !== null)).toBe(true);

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  // A periodic deck refresh must not close a menu or a modal under its reader.
  await actions.click();
  await page.waitForTimeout(3500);
  await expect(end).toBeVisible();
  await end.click();
  await page.waitForTimeout(3500);
  await expect(dialog).toBeVisible();
  expect(await dialog.evaluate((element) => element.matches(":modal"))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});
