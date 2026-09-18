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
// updates, that the Advanced disclosure survives a re-render, and that the credential field
// is a masked input whose value never leaves the page after it is submitted.
//
// Rewritten for the one-list design in docs/design-qa/fleet-ux-review-2026-09-18.md §5.

const TOKEN = "ouroboros-browser-test-token-000000000000";

// A device of this test's own. A deployment leaves a journal behind and the row it names
// stops reading as an untouched peer — correctly, and for the life of this server. One
// server serves both projects, so the row has to be private to the test *and* the project
// or the second run looks at the first run's leftovers.
function peer(index) {
  const offset = test.info().project.name === "mobile-chromium" ? 5 : 0;
  const number = index + offset;
  const name = "fixture-peer-" + String(number).padStart(2, "0");
  return { name: name, address: "100.100.7." + number };
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
async function tabUntil(page, predicate, limit = 80) {
  for (let step = 0; step < limit; step++) {
    await page.keyboard.press("Tab");
    const where = await focused(page);
    if (where && predicate(where)) return where;
  }
  throw new Error("tabbed " + limit + " times without reaching the target");
}

test("one list, one action per row, and the work's machine named once", async ({ page }) => {
  await openDevices(page);

  // §5.1's quiet line, and not the boxed paragraph it replaced.
  await expect(page.locator("[data-ouro-deployment-host]").first()).toContainText("Actions run on");
  await expect(page.getByText("not on the computer showing this page")).toHaveCount(0);

  // One list. No Fleet/Available split, and no legend explaining the page's own words.
  await expect(page.locator("#devices-list")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Fleet devices" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Available on this network" })).toHaveCount(0);
  await expect(page.getByText("What each state means")).toHaveCount(0);

  // This machine comes first and is labelled after the host's OS.
  const first = page.locator("#devices-list > li").first();
  await expect(first).toHaveAttribute("data-state", /this_device/);
  await expect(first.locator(".ouro-devices-label")).toContainText(/This (Mac|machine)/);

  // The state reads as words; the code is only ever an attribute.
  const untouched = page.locator('[data-address="' + peer(1).address + '"]');
  await expect(untouched).toContainText("not set up");
  await expect(untouched).not.toContainText("discovered_installation_unknown");
  await expect(untouched).not.toContainText("Discovered peer; Ouroboros installation unknown");

  // Presence is a dot, a word and a relative time — never an ISO instant on a row.
  await expect(untouched.locator(".ouro-devices-presence")).toContainText("online");
  await expect(page.locator("#devices-list")).not.toContainText("2026-09-01T00:00:00Z");

  // A platform with no release offers no deployment — §5.1's "a device that cannot be acted
  // on shows no button" — but keeps the way in to the reason the same sentence promises.
  const blocked = page.locator('[data-state="unsupported_platform"]').first();
  await expect(blocked).toContainText("run Ouroboros");
  await expect(blocked.getByRole("button", { name: "Add to fleet" })).toHaveCount(0);
  await expect(blocked.getByRole("button", { name: "Details" })).toBeVisible();

  await blocked.getByRole("button", { name: "Details" }).click();
  await expect(page.locator("#ouro-deploy")).toContainText("nothing to offer on its row");
  await page.keyboard.press("Escape");
});

test("the drawer opens, traps focus and gives it back, under the keyboard alone", async ({
  page
}) => {
  await openDevices(page);

  // Tab to the Add to fleet button rather than clicking it: the whole point is that a
  // keyboard can reach it.
  const opener = await tabUntil(page, where => where.text === "Add to fleet");
  expect(opener.tag).toBe("button");
  await page.keyboard.press("Enter");

  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toBeVisible();
  await expect(drawer).toHaveAttribute("aria-modal", "true");

  // Focus went into the dialog by itself.
  await expect.poll(async () => (await focused(page)).inDialog).toBe(true);

  // And Escape closes it and puts focus back where it came from — without cancelling the
  // setup, which has not started yet at this step.
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await expect.poll(async () => (await focused(page)).text).toBe("Add to fleet");
});

test("the Advanced disclosure stays open while the form above it is typed in", async ({
  page
}) => {
  await openDevices(page);

  const device = peer(5);
  await page
    .locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]')
    .click();

  const advanced = page.locator("details.ouro-devices-advanced");
  await expect(advanced).not.toHaveAttribute("open", /.*/);

  await page.locator("details.ouro-devices-advanced > summary").click();
  await expect(advanced).toHaveAttribute("open", /.*/);

  // Finding 6, in the browser that found it: `<details>` carried no `open` attribute and
  // the event that recorded the choice was read by nothing, so every keystroke in the form
  // above collapsed it.
  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.locator("#deploy-ssh-user").press("y");
  await expect(advanced).toHaveAttribute("open", /.*/);
  await expect(page.locator("#deploy-port")).toBeVisible();
});

test("the whole setup: host key, a masked password, review, progress, finish", async ({
  page
}) => {
  await openDevices(page);

  const device = peer(2);
  await page
    .locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]')
    .click();
  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toBeVisible();

  // Nobody has started anything here, so nothing may suggest somebody else did.
  await expect(page.locator("[data-ouro-takeover]")).toHaveCount(0);

  // 1. The form. §5.2: a name pre-filled from `suggested_machine`, a read-only address
  // because this one came from the list, an SSH user, and no authentication picker.
  await expect(drawer).toContainText("Add " + device.name + " to your fleet");
  await expect(page.locator("#deploy-machine")).toHaveValue(device.name);
  await expect(page.locator("#deploy-address")).toHaveValue(device.address);
  await expect(page.locator("#deploy-address")).toHaveAttribute("readonly", "");
  await expect(page.locator("#deploy-ssh-user")).toHaveAttribute("required", "");
  await expect(page.locator("#deploy-identity-kind")).toHaveCount(0);
  await expect(page.getByText("Authentication method")).toHaveCount(0);

  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.getByRole("button", { name: "Connect", exact: true }).click();

  // 2. The host key, named after the address it belongs to.
  await expect(page.getByRole("heading", { name: /First time connecting to/ })).toBeVisible();
  await expect(drawer).toContainText("SHA256:fixtureFingerprintNotARealHostKey");
  await expect(drawer).toContainText("ssh-ed25519");
  await expect(drawer).toContainText("Check this fingerprint on the device itself");
  await page.getByRole("button", { name: "Trust and continue" }).click();

  // 3. The password. Masked, with no change event on the form, and emptied afterwards.
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

  // 4. Review. Five plain lines, the digest under them, and the whole document behind a
  // disclosure — the digest covers the document, not the five lines.
  await expect(page.getByRole("heading", { name: "Ready to deploy" })).toBeVisible();
  await expect(drawer).toContainText("Install ouro 0.1.8 (Linux x86-64)");
  await expect(drawer).toContainText("/usr/local/bin/ouro");
  await expect(drawer).toContainText("Join the fleet as " + device.name);
  await expect(drawer).toContainText("Start at login as a user service");
  await expect(drawer).toContainText("Update 1 roster");

  // Sixty-four lowercase hex, and the page's own sha256 of the plan above it — approval is
  // not offered for anything else.
  await expect(page.locator("[data-ouro-plan-digest]")).toHaveText(/^[0-9a-f]{64}$/);

  // The document's own key names are never what an operator is shown.
  await page.getByText("Everything in this plan").click();
  for (const label of ["operation", "action", "machine", "address", "ssh", "install", "startup"]) {
    await expect(drawer.locator("dt", { hasText: new RegExp("^" + label + "$") })).toHaveCount(1);
  }
  await expect(drawer.locator("dt", { hasText: /^install_path$/ })).toHaveCount(0);
  await expect(drawer.locator("dt", { hasText: /^data_dir$/ })).toHaveCount(0);

  // The password is gone from the page the moment its step is over: not in any input, and
  // not anywhere in the rendered document.
  await expect(page.locator("[data-ouro-secret]")).toHaveCount(0);
  expect(await page.content()).not.toContain(password);

  await page.locator('button[phx-click="approve"]').click();

  // 5. Progress. A polite live region carries each step change, and the six-mark strip is
  // drawn with "not reported yet" where nothing has been.
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
        // The sentence is the region's first text node; a visually-hidden counter beside
        // it is what makes two identical sentences two announcements rather than one
        // silent no-op, and it is not part of what is said.
        const said = () => {
          const first = region.querySelector("span") || region.firstChild;
          return ((first && first.textContent) || "").trim();
        };
        const observer = new MutationObserver(() => {
          const text = said();
          if (text && seen[seen.length - 1] !== text) seen.push(text);
          if (/^Done\.$/.test(text)) {
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
  expect(announced[announced.length - 1]).toBe("Done.");

  // The strip names all six stages, short.
  for (const stage of ["Inspect", "Install", "Join fleet", "Start at login", "Connect", "Ready"]) {
    await expect(drawer.locator(".ouro-devices-strip")).toContainText(stage);
  }
  // `install_binary` is the engine's name and belongs to the install stage; a prefix match
  // would have filed it nowhere.
  await expect(drawer.locator('[data-step="install"]')).toContainText(
    "Install the `ouro` binary on " + device.name
  );
  await expect(drawer.locator('[data-step="membership"]')).toContainText(
    "Update a roster on fixture-studio"
  );

  // 6. Finish. §5.2: "<name> is in your fleet", Open and Done, and nothing that acts on
  // this runtime instead of the machine that was just added.
  await expect(
    page.getByRole("heading", { name: device.name + " is in your fleet" })
  ).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole("link", { name: "Open", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Done", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Configure model" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Run test task" })).toHaveCount(0);

  // And nothing in the finished page is the password either, including the address bar.
  expect(page.url()).not.toContain(password);
  expect(await page.content()).not.toContain(password);
});

test("a finished operation changes what its row says", async ({ page }) => {
  await openDevices(page);

  const device = peer(3);
  const row = page.locator('[data-address="' + device.address + '"]');
  await expect(row).toContainText("not set up");

  await page
    .locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]')
    .click();
  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: /First time connecting/ })).toBeVisible();

  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();

  // The operation is the freshest thing known about this device, and the row says so
  // rather than going back to reading as an untouched peer with an Add to fleet button.
  await expect(row).toContainText("waiting for you");
  await expect(row.getByRole("button", { name: "Add to fleet" })).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Continue" })).toBeVisible();
});

test("closing the drawer keeps the operation, and the address reopens it", async ({ page }) => {
  await openDevices(page);

  const device = peer(4);
  await page
    .locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]')
    .click();
  await page.locator("#deploy-ssh-user").fill("deploy");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: /First time connecting/ })).toBeVisible();

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
