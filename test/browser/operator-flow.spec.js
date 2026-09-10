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

// A page reached by a full load renders dead first: its Start button is enabled before
// the LiveView has joined, and a submit sent in that window is dropped by the client
// without a frame or an error. A reader cannot click inside it; a runner can, and does
// on a fast machine. Start is clicked only once the root reports the join.
async function liveConnected(page) {
  await expect(page.locator("[data-phx-main]")).toHaveClass(/\bphx-connected\b/);
}

// The top bar names the cluster's machines as a presence indicator, one dot each. There
// is no machines page behind it: the fleet product went with the reduction
// (docs/proposals/core.md §3 D4), and the cluster's membership is a file operation.
function machinesPresence(page) {
  return page
    .locator(".ouro-topbar")
    .getByRole("img", { name: /^Machines — \d+ connected of \d+$/ });
}

test("sign-in recovery and progressive session setup", async ({ page }) => {
  await signIn(page);
  await expect(machinesPresence(page)).toBeVisible();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();

  // The round trip through a second page and back, the way the machines page used to
  // prove that navigation keeps the socket and the titles follow the page.
  await page.locator(".ouro-topbar").getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page).toHaveTitle("Settings · Ouroboros");
  await page.getByRole("link", { name: "← Sessions", exact: true }).click();
  await expect(page).toHaveTitle("Sessions · Ouroboros");

  await page.getByRole("link", { name: "New session", exact: true }).click();
  await expect(page).toHaveTitle("New session · Ouroboros");
  await expect(page.locator("#workspace")).toBeVisible();
  await expectMinimumTarget(page.getByRole("combobox", { name: "Computer", exact: true }));
  await expect(page.locator("#initial-message")).toBeVisible();
  await expectMinimumTarget(page.locator("#workspace"));
  await expectMinimumTarget(page.locator("#initial-message"));

  // Native is the only provider, so the advanced block holds the model, the thinking
  // level and the file-access posture; the provider select it used to hold is gone.
  const advanced = page.locator("details.ouro-new-advanced");
  const thinking = page.getByRole("combobox", { name: "Thinking", exact: true });
  const fileAccess = page.getByRole("group", { name: "File access", exact: true });
  await expect(advanced).not.toHaveAttribute("open", "");
  await expect(thinking).not.toBeVisible();
  await expect(fileAccess).not.toBeVisible();

  await advanced.locator("summary").click();
  await expect(thinking).toBeVisible();
  await expect(fileAccess).toBeVisible();
  await expectMinimumTarget(thinking);
  await expectMinimumTarget(page.getByRole("button", { name: "Start session" }));
});

test("session controls stay reachable and dialogs are modal", async ({ page }, testInfo) => {
  await signIn(page);
  await page.getByRole("link", { name: "New session", exact: true }).click();

  await liveConnected(page);
  const start = page.getByRole("button", { name: "Start session" });
  await expect(start).toBeEnabled();
  await start.click();
  await expect(page).toHaveURL(/\/s\/interactive\//);
  await expect(machinesPresence(page)).toBeVisible();
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
  await liveConnected(another);
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
