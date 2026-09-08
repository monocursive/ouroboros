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
  const machines = page.locator(".ouro-topbar").getByRole("link", { name: /Machines/ });
  await expect(machines).toBeVisible();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await machines.click();
  await expect(page).toHaveTitle("Machines · Ouroboros");
  await page.getByRole("link", { name: "Sessions", exact: true }).click();

  await page.getByRole("link", { name: "New session", exact: true }).click();
  await expect(page).toHaveTitle("New session · Ouroboros");
  await expect(page.locator("#workspace")).toBeVisible();
  await expectMinimumTarget(page.getByRole("combobox", { name: "Computer", exact: true }));
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
  await expect(page.locator(".ouro-topbar").getByRole("link", { name: /Machines/ })).toBeVisible();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();

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
  await actions.focus();
  await expect(actions).toBeFocused();

  // A new session moves this row down the rail. Its open menu and keyboard focus
  // must follow the session instead of staying on the row's old position.
  const another = await page.context().newPage();
  await another.goto("/new");
  await another.getByRole("button", { name: "Start session" }).click();
  await expect(another).toHaveURL(/\/s\/interactive\//);
  const newSessionPath = new URL(another.url()).pathname;
  await another.close();
  await page.bringToFront();
  await expect(page.locator(`.ouro-row-wrap > a[href="${newSessionPath}"]`)).toHaveCount(1);
  await page.waitForTimeout(3500);
  await expect(end).toBeVisible();
  await expect(actions).toBeFocused();
  await end.click();
  await page.waitForTimeout(3500);
  await expect(dialog).toBeVisible();
  expect(await dialog.evaluate((element) => element.matches(":modal"))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});
