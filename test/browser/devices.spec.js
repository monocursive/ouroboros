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

// A device of this test's own. A deployment leaves a journal behind and the row it names
// stops reading as an untouched peer — correctly, and for the life of this server. One
// server serves both projects, so the row has to be private to the test *and* the project
// or the second run looks at the first run's leftovers.
function peer(index) {
  const offset = test.info().project.name === "mobile-chromium" ? 5 : 0;
  const number = index + offset;
  return {
    name: "fixture-peer-" + String(number).padStart(2, "0"),
    address: "100.100.7." + number
  };
}

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
  const untouched = page.locator('[data-address="' + peer(1).address + '"]');
  await expect(untouched).toContainText("Discovered peer; Ouroboros installation unknown");
  await expect(untouched).not.toContainText("discovered_installation_unknown");

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
  await expect(page.locator('[data-address="' + peer(1).address + '"]')).toHaveCount(0);
  await expect(page.getByText("fixture-toaster").first()).toBeVisible();

  await search.fill("");
  await expect(page.locator('[data-address="' + peer(1).address + '"]')).toBeVisible();

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

  const device = peer(2);
  await page.locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]').click();
  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toBeVisible();

  // Nobody has started anything here, so nothing may suggest somebody else did.
  await expect(page.locator("[data-ouro-takeover]")).toHaveCount(0);

  // 1. Select and connect. The username is required and the advanced fields are behind a
  // disclosure rather than in front of every deployment.
  await expect(page.locator("#deploy-address")).toHaveValue(device.address);
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

  // 4. Review. The plan in the CLI's own labels, and approval applies exactly its digest.
  await expect(page.getByRole("heading", { name: "Review this plan" })).toBeVisible();
  for (const label of ["operation", "action", "machine", "address", "ssh", "identity", "executable", "data dir", "install", "startup", "members"]) {
    await expect(drawer.locator("dt", { hasText: new RegExp("^" + label + "$") })).toHaveCount(1);
  }
  // The document's own key names are never what an operator is shown.
  await expect(drawer.locator("dt", { hasText: /^install_path$/ })).toHaveCount(0);
  await expect(drawer.locator("dt", { hasText: /^data_dir$/ })).toHaveCount(0);
  await expect(drawer).toContainText("ouro 0.1.8 (x86_64-unknown-linux-gnu)");
  await expect(drawer).toContainText("/usr/local/bin/ouro");
  await expect(drawer).toContainText("What approving this grants");
  // Sixty-four lowercase hex, and the page's own sha256 of the plan above it — approval is
  // not offered for anything else.
  await expect(page.locator("[data-ouro-plan-digest]")).toHaveText(/^[0-9a-f]{64}$/);

  // The password is gone from the page the moment its step is over: not in any input, and
  // not anywhere in the rendered document.
  await expect(page.locator("[data-ouro-secret]")).toHaveCount(0);
  expect(await page.content()).not.toContain(password);

  await page.locator('button[phx-click="approve"]').click();

  // 5. Progress. A polite live region carries each step change, and every stage the
  // proposal names is drawn — with "not reported yet" where nothing has been.
  const live = page.locator("#ouro-deploy-live");
  await expect(live).toHaveAttribute("aria-live", "polite");

  // Every sentence the region took, not whichever one it happened to hold when this
  // polled: the steps go past in under a second, and "it said something at the end" is not
  // the claim. A screen reader hears each of these.
  const announced = await page.evaluate(
    () =>
      new Promise(resolve => {
        const region = document.getElementById("ouro-deploy-live");
        const seen = [];
        // The sentence is the region's first text node; the counter beside it is what makes
        // two identical sentences two announcements rather than one silent no-op, and it is
        // not part of what is said.
        const said = () => ((region.firstChild && region.firstChild.textContent) || "").trim();
        const observer = new MutationObserver(() => {
          const text = said();
          if (text && seen[seen.length - 1] !== text) seen.push(text);
          if (/^Completed\.$/.test(text)) {
            observer.disconnect();
            resolve(seen);
          }
        });
        observer.observe(region, { childList: true, characterData: true, subtree: true });
        setTimeout(() => {
          observer.disconnect();
          resolve(seen);
        }, 20000);
      })
  );

  expect(announced).toContain("Install the `ouro` binary on " + device.name + ": running.");
  expect(announced).toContain("Update a roster on fixture-studio: done.");
  expect(announced).toContain("Connect on " + device.name + ": done.");
  expect(announced[announced.length - 1]).toBe("Completed.");
  await expect(drawer).toContainText("Install Ouroboros if it is missing");
  await expect(drawer).toContainText("Check readiness");
  // `install_binary` is the engine's name and belongs to the install stage; a prefix match
  // would have filed it nowhere.
  await expect(drawer).toContainText("Install the `ouro` binary on " + device.name);
  await expect(drawer).toContainText("Update a roster on fixture-studio");

  // 6. Finish. Readiness is read from the readiness step, which the engine really records
  // as `skipped`, and the next step is the worker's own sentence.
  await expect(page.getByRole("heading", { name: "Completed" })).toBeVisible({ timeout: 15000 });
  await expect(drawer).toContainText(device.name + " joined this fleet");
  await expect(drawer).toContainText("Readiness was not established from here.");
  await expect(drawer).toContainText("Configure a model on " + device.name + ", then run a test task.");
  await expect(drawer).toContainText("What this operation could not establish");
  await expect(page.getByRole("link", { name: "Open device" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Configure model" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Run test task" })).toBeVisible();

  // And nothing in the finished page is the password either, including the address bar.
  expect(page.url()).not.toContain(password);
  expect(await page.content()).not.toContain(password);
});

test("a finished operation changes what its row says", async ({ page }) => {
  await openDevices(page);

  const device = peer(3);
  const row = page.locator('[data-address="' + device.address + '"]');
  await expect(row).toContainText("Discovered peer; Ouroboros installation unknown");

  await page.locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]').click();
  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.getByRole("button", { name: "Inspect this device" }).click();
  await expect(page.getByRole("heading", { name: "Verify this host before continuing" })).toBeVisible();

  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();

  // The operation is the freshest thing known about this device, and the row says so
  // rather than going back to reading as an untouched peer with a Deploy button.
  await expect(row).toContainText("Continue setup");
  await expect(row.getByRole("button", { name: "Deploy Ouroboros" })).toHaveCount(0);
});

test("closing the drawer keeps the operation, and the address reopens it", async ({ page }) => {
  await openDevices(page);

  const device = peer(4);
  await page.locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]').click();
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
