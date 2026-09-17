const { test, expect } = require("@playwright/test");

// The Devices page in a real browser, driven the way a person without a mouse drives it.
//
// The runtime behind it is `test/support/browser_runtime.exs`, which stands up a fake `ouro`
// and a scripted fake deployment worker (`Ouroboros.Test.BrowserFleet`). No SSH client, no
// network and no credential store is anywhere in this path: the password typed below goes to
// a Unix socket inside the same BEAM and is dropped.
//
// What only a browser can prove, and therefore what this file is for: that the drawer opens
// and closes under the keyboard alone, that focus goes into it and comes back out to the
// control that opened it, that the live region is a real `aria-live` region the browser
// updates, and that the credential field is a masked input whose value never leaves the page
// after it is submitted.

const TOKEN = "ouroboros-browser-test-token-000000000000";

async function liveConnected(page) {
  await expect(page.locator("[data-phx-main]")).toHaveClass(/\bphx-connected\b/);
}

async function openDevices(page) {
  await page.goto("/auth");
  await page.getByLabel("Access token").fill(TOKEN);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/$/);
  await page.goto("/devices");
  await liveConnected(page);
}

// The focused element's own description, for asserting where the keyboard has landed.
function focused(page) {
  return page.evaluate(() => {
    const el = document.activeElement;
    if (!el) return null;
    return {
      tag: el.tagName.toLowerCase(),
      type: el.getAttribute("type"),
      id: el.id,
      text: (el.textContent || "").trim().slice(0, 60),
      inDialog: Boolean(el.closest("#ouro-deploy"))
    };
  });
}

// Tab until the predicate holds, so a test does not depend on the exact number of controls
// between two points in the page.
async function tabUntil(page, predicate, limit = 60) {
  for (let step = 0; step < limit; step++) {
    await page.keyboard.press("Tab");
    const where = await focused(page);
    if (where && predicate(where)) return where;
  }
  throw new Error("tabbed " + limit + " times without reaching the target");
}

test("the inventory names the deployment host and says the state in words", async ({ page }) => {
  await openDevices(page);

  await expect(page.locator("[data-ouro-deployment-host]").first()).toContainText("Deploying from");
  await expect(page.locator("[data-ouro-deployment-host]").first()).toContainText("local user");
  await expect(page.getByText("not on the computer showing this page")).toBeVisible();

  await expect(page.getByRole("heading", { name: "Fleet devices" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Available on this network" })).toBeVisible();

  // The state reads as words; the code is only ever an attribute.
  const peer = page.locator('[data-state="discovered_installation_unknown"]').first();
  await expect(peer).toContainText("Discovered peer; Ouroboros installation unknown");
  await expect(peer).not.toContainText("discovered_installation_unknown");

  // A blocked platform explains the blocker instead of offering a deployment.
  const blocked = page.locator('[data-state="unsupported_platform"]').first();
  await expect(blocked).toContainText("Deployment is disabled for this device");
  await expect(blocked.getByRole("button", { name: "Deploy Ouroboros" })).toHaveCount(0);
});

test("search and the section filter work from the keyboard", async ({ page }) => {
  await openDevices(page);

  const search = page.locator("#devices-search");
  await search.focus();
  await search.fill("toaster");
  await expect(page.getByText("fixture-vps")).toHaveCount(0);
  await expect(page.getByText("fixture-toaster").first()).toBeVisible();

  await search.fill("");
  await expect(page.getByText("fixture-vps").first()).toBeVisible();

  // The filter buttons are buttons, so Enter is the whole interaction.
  const fleetFilter = page.getByRole("button", { name: "Fleet", exact: true });
  await fleetFilter.focus();
  await page.keyboard.press("Enter");
  await expect(fleetFilter).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("heading", { name: "Available on this network" })).toHaveCount(0);
});

test("the drawer opens, traps focus and gives it back, under the keyboard alone", async ({ page }) => {
  await openDevices(page);

  // Tab to the Deploy button rather than clicking it: the whole point is that a keyboard
  // can reach it.
  const opener = await tabUntil(page, where => where.text === "Deploy Ouroboros");
  expect(opener.tag).toBe("button");
  await page.keyboard.press("Enter");

  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toBeVisible();
  await expect(drawer).toHaveAttribute("aria-modal", "true");

  // Focus went into the dialog by itself.
  await expect.poll(async () => (await focused(page)).inDialog).toBe(true);

  // And Escape closes it and puts focus back where it came from — without cancelling the
  // deployment, which has not started yet at this step.
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await expect.poll(async () => (await focused(page)).text).toBe("Deploy Ouroboros");
});

test("the whole deployment: host trust, a masked credential, review, progress, finish", async ({
  page
}) => {
  await openDevices(page);

  await page.locator('button[phx-value-address="100.100.0.44"]').click();
  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toBeVisible();

  // 1. Select and connect. The username is required and the advanced fields are behind a
  // disclosure rather than in front of every deployment.
  await expect(page.locator("#deploy-address")).toHaveValue("100.100.0.44");
  await expect(page.locator("#deploy-ssh-user")).toHaveAttribute("required", "");
  await expect(page.getByText("Advanced — port, identity and paths")).toBeVisible();

  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.getByRole("button", { name: "Inspect this device" }).click();

  // 2. Host trust, from the challenge's own metadata, with the verify-independently rule.
  await expect(page.getByRole("heading", { name: "Verify this host before continuing" })).toBeVisible();
  await expect(drawer).toContainText("SHA256:fixtureFingerprintNotARealHostKey");
  await expect(drawer).toContainText("ssh-ed25519");
  await expect(drawer).toContainText("Verify this fingerprint independently");
  await page.getByRole("button", { name: "Trust this host and continue" }).click();

  // 3. The credential. Masked, with no change event on the form, and emptied afterwards.
  const secret = page.locator("[data-ouro-secret]");
  await expect(secret).toBeVisible();
  await expect(secret).toHaveAttribute("type", "password");
  await expect(page.locator("#ouro-deploy-auth")).not.toHaveAttribute("phx-change", /.*/);

  // The field takes focus by itself, so a keyboard operator types straight into it.
  await expect(secret).toBeFocused();

  const password = "browser-fixture-password-" + Date.now();
  await page.keyboard.type(password);
  await expect(secret).toHaveValue(password);
  await page.keyboard.press("Enter");

  // 4. Review. The plan and its digest, and approval applies exactly that digest.
  await expect(page.getByRole("heading", { name: "Review this plan" })).toBeVisible();
  await expect(drawer).toContainText("0.1.8");
  await expect(drawer).toContainText("/usr/local/bin/ouro");
  await expect(page.locator("[data-ouro-plan-digest]")).toHaveText("sha256:fixture-plan-digest");

  // The password is gone from the page the moment its step is over: not in any input, and
  // not anywhere in the rendered document.
  await expect(page.locator("[data-ouro-secret]")).toHaveCount(0);
  expect(await page.content()).not.toContain(password);

  await page.locator('button[phx-click="approve"]').click();

  // 5. Progress. A polite live region carries each step change, and every stage the
  // proposal names is drawn — with "not reported yet" where nothing has been.
  const live = page.locator("#ouro-deploy-live");
  await expect(live).toHaveAttribute("aria-live", "polite");
  await expect(live).toContainText("install: done.", { timeout: 15000 });
  await expect(drawer).toContainText("Install Ouroboros if it is missing");
  await expect(drawer).toContainText("Check readiness");

  // 6. Finish, with the three actions the proposal names, offered on observed readiness.
  await expect(page.getByRole("heading", { name: "Completed" })).toBeVisible({ timeout: 15000 });
  await expect(drawer).toContainText("This device reported that it is ready.");
  await expect(page.getByRole("link", { name: "Open device" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Configure model" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Run test task" })).toBeVisible();

  // And nothing in the finished page is the password either, including the address bar.
  expect(page.url()).not.toContain(password);
  expect(await page.content()).not.toContain(password);
});

test("closing the drawer keeps the operation, and the address reopens it", async ({ page }) => {
  await openDevices(page);

  await page.locator('button[phx-value-address="100.100.0.44"]').click();
  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.getByRole("button", { name: "Inspect this device" }).click();
  await expect(page.getByRole("heading", { name: "Verify this host before continuing" })).toBeVisible();

  const url = new URL(page.url());
  const operation = url.searchParams.get("operation");
  expect(operation).toMatch(/^[0-9a-f]{16}$/);

  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.locator("#ouro-deploy")).toHaveCount(0);
  await expect(page).toHaveURL(/\/devices$/);

  // Reopened by id, from a fresh page load: the operation outlived the drawer.
  await page.goto("/devices?operation=" + operation);
  await liveConnected(page);
  await expect(page.locator("#ouro-deploy")).toBeVisible();
  await expect(page.locator("[data-ouro-operation]")).toHaveText(operation);
});
