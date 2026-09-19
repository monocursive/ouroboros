const { test, expect } = require("@playwright/test");

// The Devices page in a real browser, driven the way a person without a mouse drives it.
//
// The runtime behind it is `test/support/browser_runtime.exs`, which stands up one fake
// `ouro` (`Ouroboros.Test.BrowserFleet`). That executable answers `fleet devices --json` with
// a frozen inventory and, for a `--frames` run, speaks the frames protocol of
// docs/proposals/fleet-kiss.md §8 on its own stdio. No SSH client, no network and no
// credential store is anywhere in this path: the password typed below goes to the stdin of a
// shell script in a pipe and is dropped.
//
// What only a browser can prove, and therefore what this file is for: that the drawer opens
// and closes under the keyboard alone, that focus goes into it and comes back out to the
// control that opened it, that the live region is a real `aria-live` region the browser
// updates, that the Advanced disclosure survives a re-render, and that the credential field
// is a masked input whose value never leaves the page after it is submitted.

const TOKEN = "ouroboros-browser-test-token-000000000000";

// A device of this test's own. A deployment leaves a journal behind and the row it names
// stops reading as an untouched peer — correctly, and for the life of this server. One
// server serves both projects, so the row has to be private to the test *and* the project
// or the second run looks at the first run's leftovers.
//
// Six rows per project, and the fixture scripts three of them: `peer(3)` asks for a key's
// passphrase, `peer(4)` waits to be cancelled, and `peer(5)` fails.
function peer(index) {
  const offset = test.info().project.name === "mobile-chromium" ? 6 : 0;
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
async function tabUntil(page, predicate, limit = 100) {
  for (let step = 0; step < limit; step++) {
    await page.keyboard.press("Tab");
    const where = await focused(page);
    if (where && predicate(where)) return where;
  }
  throw new Error("tabbed " + limit + " times without reaching the target");
}

// Open the add drawer on a row and submit its form.
async function startAdd(page, device, user = "fixture") {
  await page
    .locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]')
    .click();
  await page.locator("#deploy-ssh-user").fill(user);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
}

test("one list, one action per row, and the work's machine named once", async ({ page }) => {
  await openDevices(page);

  // The quiet line, and not the boxed paragraph it replaced.
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

  // A platform with no release offers no deployment — "a device that cannot be acted on
  // shows no button" — but keeps the way in to the reason.
  const blocked = page.locator('[data-state="unsupported_platform"]').first();
  await expect(blocked).toContainText("run Ouroboros");
  await expect(blocked.getByRole("button", { name: "Add to fleet" })).toHaveCount(0);
  await expect(blocked.getByRole("button", { name: "Details" })).toBeVisible();

  await blocked.getByRole("button", { name: "Details" }).click();
  await expect(page.locator("#ouro-deploy")).toContainText("nothing to offer on its row");
  await page.keyboard.press("Escape");
});

test("the discovery notice quotes the client and claims nothing about a build", async ({
  page
}) => {
  await openDevices(page);

  // This fixture's client answers, so there is no notice at all — and in particular not the
  // guess about a version that the 2026-09-18 review found on a Mac whose Tailscale app
  // printed "The Tailscale GUI failed to start" and exited 0.
  await expect(page.getByText("may be older than the client")).toHaveCount(0);
  await expect(page.getByText("Tailscale did not answer from this runtime")).toHaveCount(0);
  await expect(page.locator("#devices-list > li").nth(1)).toBeVisible();
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

  // peer(2) is the one the happy script runs for; opening its form and never submitting it
  // leaves no journal, so this test and that one can share a row.
  const device = peer(2);
  await page
    .locator('button[phx-click="deploy"][phx-value-address="' + device.address + '"]')
    .click();

  const advanced = page.locator("details.ouro-devices-advanced");
  await expect(advanced).not.toHaveAttribute("open", /.*/);

  await page.locator("details.ouro-devices-advanced > summary").click();
  await expect(advanced).toHaveAttribute("open", /.*/);

  // `<details>` is bound to its assign, so a `phx-change` on the form above it re-renders it
  // open rather than collapsing it on every keystroke.
  await page.locator("#deploy-ssh-user").fill("fixture");
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

  // Nobody has started anything here, so nothing may suggest somebody else did — and §10
  // deletes the two panels that used to say so.
  await expect(page.locator("[data-ouro-takeover]")).toHaveCount(0);
  await expect(page.locator("[data-ouro-rebind]")).toHaveCount(0);

  // 1. The form: a name pre-filled from `suggested_machine`, a read-only address because
  // this one came from the list, an SSH user, and no authentication picker.
  await expect(drawer).toContainText("Add " + device.name + " to your fleet");
  await expect(page.locator("#deploy-machine")).toHaveValue(device.name);
  await expect(page.locator("#deploy-address")).toHaveValue(device.address);
  await expect(page.locator("#deploy-address")).toHaveAttribute("readonly", "");
  await expect(page.locator("#deploy-ssh-user")).toHaveAttribute("required", "");
  await expect(page.locator("#deploy-identity-kind")).toHaveCount(0);
  await expect(page.getByText("Authentication method")).toHaveCount(0);

  await page.locator("#deploy-ssh-user").fill("fixture");
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
  await expect(drawer).toContainText("attempt 1 of 3");

  // The field takes focus by itself, so a keyboard operator types straight into it.
  await expect(secret).toBeFocused();

  const password = "browser-fixture-password-" + Date.now();
  await page.keyboard.type(password);
  await expect(secret).toHaveValue(password);
  await page.keyboard.press("Enter");

  // 4. Review: the plan's own lines, and nothing else. §10 deletes the digest, the
  // idempotency key and the second copy of the plan behind a disclosure.
  await expect(page.getByRole("heading", { name: "Ready to deploy" })).toBeVisible();
  await expect(drawer).toContainText("Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro");
  await expect(drawer).toContainText("Join this fleet as the target");
  await expect(drawer).toContainText("Start at login as a user service");
  await expect(page.locator("[data-ouro-plan-digest]")).toHaveCount(0);
  await expect(page.getByText("plan digest")).toHaveCount(0);
  await expect(page.getByText("Everything in this plan")).toHaveCount(0);

  // The password is gone from the page the moment its step is over: not in any input, and
  // not anywhere in the rendered document.
  await expect(page.locator("[data-ouro-secret]")).toHaveCount(0);
  expect(await page.content()).not.toContain(password);

  await page.locator('button[phx-click="approve"]').click();

  // 5. Progress. A polite live region carries each step change.
  const live = page.locator("#ouro-deploy-live");
  await expect(live).toHaveAttribute("aria-live", "polite");

  // Every sentence the region took, not whichever one it happened to hold when this polled:
  // the steps go past in under a second, and "it said something at the end" is not the
  // claim. A screen reader hears each of these.
  const announced = await page.evaluate(
    () =>
      new Promise(resolve => {
        const region = document.getElementById("ouro-deploy-live");
        const seen = [];
        // The sentence is the region's first text node; a visually-hidden counter beside it
        // is what makes two identical sentences two announcements rather than one silent
        // no-op, and it is not part of what is said.
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

  expect(announced).toContain("Install Ouroboros: done.");
  expect(announced).toContain("Connect: done.");
  expect(announced[announced.length - 1]).toBe("Done.");

  // The strip names the add flow's six stages, short, and none of the others'.
  for (const stage of ["Inspect", "Install", "Join fleet", "Start at login", "Start", "Connect"]) {
    await expect(drawer.locator(".ouro-devices-strip")).toContainText(stage);
  }
  await expect(drawer.locator('[data-step="create"]')).toHaveCount(0);
  await expect(drawer.locator('[data-step="install"]')).toContainText("/usr/local/bin/ouro");

  // 6. Finish: "<name> is in your fleet", Open and Done, and nothing that acts on this
  // runtime instead of the machine that was just added.
  //
  // Scoped to the drawer, every one of them. "Open" is also the self row's own action and
  // the action a completed operation leaves on its row.
  await expect(
    drawer.getByRole("heading", { name: device.name + " is in your fleet" })
  ).toBeVisible({ timeout: 15000 });
  await expect(drawer.getByRole("link", { name: "Open", exact: true })).toBeVisible();
  await expect(drawer.getByRole("button", { name: "Done", exact: true })).toBeVisible();
  await expect(drawer.getByRole("link", { name: "Configure model" })).toHaveCount(0);
  await expect(drawer.getByRole("link", { name: "Run test task" })).toHaveCount(0);
  await expect(drawer.locator(".ouro-devices-strip")).not.toContainText("not reported yet");

  // And nothing in the finished page is the password either, including the address bar.
  expect(page.url()).not.toContain(password);
  expect(await page.content()).not.toContain(password);
});

test("add by address is the same form with the address to type in", async ({ page }) => {
  await openDevices(page);

  await page.getByRole("button", { name: "Add a device by address" }).click();
  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toContainText("Add a device by address");

  // The address is a thing to be typed rather than a fact, and the name starts empty because
  // nothing has suggested one.
  await expect(page.locator("#deploy-address")).not.toHaveAttribute("readonly", /.*/);
  await expect(page.locator("#deploy-machine")).toHaveValue("");

  // A name that is not a machine name is refused here rather than three steps later.
  // A destination of this project's own. The two projects share one server, and a manual add
  // leaves an operation running against the name it was given — which the runtime now
  // refuses a second operation for, correctly.
  const manual = test.info().project.name === "mobile-chromium" ? "2" : "1";

  await page.locator("#deploy-address").fill("100.100.9." + manual);
  await page.locator("#deploy-machine").fill("not a name");
  await page.locator("#deploy-ssh-user").fill("fixture");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(drawer).toContainText("Letters, digits and hyphens only");

  await page.locator("#deploy-machine").fill("typed-by-hand-" + manual);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: /First time connecting/ })).toBeVisible();
});

test("a deployment that fails says why and offers Retry", async ({ page }) => {
  await openDevices(page);

  const device = peer(5);
  await startAdd(page, device);

  const drawer = page.locator("#ouro-deploy");
  await page.getByRole("button", { name: "Trust and continue" }).click();
  await expect(page.locator("[data-ouro-secret]")).toBeVisible();
  await page.keyboard.type("browser-fixture-failing-password");
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Ready to deploy" })).toBeVisible();
  await page.locator('button[phx-click="approve"]').click();

  await expect(drawer.getByRole("heading", { name: "Setup failed" })).toBeVisible({
    timeout: 15000
  });
  await expect(drawer).toContainText("the release archive did not verify");
  await expect(drawer.getByRole("button", { name: "Retry" }).first()).toBeVisible();
});

test("removing a member is reached from its details and reads as a removal", async ({ page }) => {
  await openDevices(page);

  const row = page.locator('[data-address="100.100.0.2"]');

  // Not on the row: the one action a member's row offers is Details.
  await expect(row.getByRole("button", { name: "Remove from fleet" })).toHaveCount(0);
  await row.getByRole("button", { name: "Details" }).click();

  const drawer = page.locator("#ouro-deploy");
  await drawer.getByRole("button", { name: "Remove from fleet" }).click();
  await expect(drawer).toContainText("Remove fixture-buildbox from the fleet");
  await expect(drawer).toContainText("Its sessions and data stay on that machine.");

  // No install path and no data directory on a form that installs nothing.
  await expect(page.locator("#deploy-install-path")).toHaveCount(0);

  await page.locator("#leave-ssh-user").fill("fixture");
  await drawer.getByRole("button", { name: "Connect", exact: true }).click();

  await page.getByRole("button", { name: "Trust and continue" }).click();
  await expect(page.locator("[data-ouro-secret]")).toBeVisible();
  await page.keyboard.type("browser-fixture-leave-password");
  await page.keyboard.press("Enter");

  // The review reads as a removal, and so does the button under it.
  await expect(page.getByRole("heading", { name: "Ready to remove" })).toBeVisible();
  await expect(drawer).toContainText("Stop Ouroboros on fixture-buildbox");
  await expect(drawer.getByRole("button", { name: "Remove", exact: true })).toBeVisible();
  await drawer.getByRole("button", { name: "Remove", exact: true }).click();

  // The removal's own three stages, and none of the add flow's.
  for (const stage of ["Stop", "Remove", "Forget"]) {
    await expect(drawer.locator(".ouro-devices-strip")).toContainText(stage);
  }
  await expect(drawer.locator('[data-step="install"]')).toHaveCount(0);

  await expect(
    drawer.getByRole("heading", { name: "fixture-buildbox is out of your fleet" })
  ).toBeVisible({ timeout: 15000 });
});

test("setting this machine up takes no account and reviews before it changes anything", async ({
  page
}) => {
  await openDevices(page);

  // The status line is the blocker sentence, and the primary button is beside it.
  await expect(page.locator(".ouro-devices-status")).toContainText(/is not in a fleet yet/);
  await page.getByRole("button", { name: /^Set up this (Mac|machine)$/ }).click();

  const drawer = page.locator("#ouro-deploy");
  await expect(drawer).toBeVisible();

  // No SSH account anywhere: this machine configures itself.
  await expect(page.locator("#leave-ssh-user")).toHaveCount(0);
  await expect(page.locator("#deploy-ssh-user")).toHaveCount(0);
  await expect(page.locator("#setup-machine")).toHaveValue("fixture-spare");
  await expect(drawer).toContainText("Ouroboros restarts once during setup");

  await page.getByRole("button", { name: "Set up", exact: true }).click();

  await expect(page.getByRole("heading", { name: "Ready to set up" })).toBeVisible();
  await expect(drawer).toContainText("Create this fleet on this machine");
  await expect(page.locator("[data-ouro-plan-digest]")).toHaveCount(0);

  await page.locator('button[phx-click="approve"]').click();

  // The setup flow's own stages, and none of the add flow's.
  for (const stage of ["Create fleet", "Stop", "Start at login", "Ready"]) {
    await expect(drawer.locator(".ouro-devices-strip")).toContainText(stage);
  }
  await expect(drawer.locator('[data-step="inspect"]')).toHaveCount(0);
});

test("Cancel setup stops the program and says what it left behind", async ({ page }) => {
  await openDevices(page);

  // peer(4) is scripted to raise a host-key question and then wait, so there is something
  // running for Cancel to stop.
  const device = peer(4);
  await startAdd(page, device);

  const drawer = page.locator("#ouro-deploy");
  await expect(page.getByRole("heading", { name: /First time connecting/ })).toBeVisible();

  // Close is not Cancel: the footer offers both, and the one beside "keeps running" leaves
  // the operation alone.
  await expect(drawer).toContainText("keeps running");
  await drawer.getByRole("button", { name: "Cancel setup", exact: true }).click();

  // The runtime answered with the state and the residue the program recorded, which is the
  // only path to this panel.
  await expect(drawer).toContainText("What this left behind");
  await expect(drawer).toContainText("a partial download at /tmp/ouro.partial");

  await expect(drawer.getByRole("heading", { name: "Cancelled" })).toBeVisible({
    timeout: 15000
  });

  await expect(drawer).toContainText("stopped at a safe boundary");
  await expect(drawer).not.toContainText("Setup failed");

  // A cancelled operation leaves the row offering to start again rather than to continue.
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();

  const row = page.locator('[data-address="' + device.address + '"]');
  await expect(row).toHaveAttribute("data-operation-state", "cancelled");
  await expect(row.getByRole("button", { name: "Continue" })).toHaveCount(0);
});

test("a passphrase is asked for as a passphrase, not as a password", async ({ page }) => {
  await openDevices(page);

  // peer(3) is scripted to ask for a key's passphrase instead of an account's password.
  const device = peer(3);
  await startAdd(page, device);

  const drawer = page.locator("#ouro-deploy");

  // The heading and the field's own label both name the key, because an operator who reads
  // "Password" over this field types the wrong secret — and tells a remote machine the
  // passphrase of a key on their own laptop.
  await expect(
    page.getByRole("heading", { name: "Passphrase for the selected key" })
  ).toBeVisible();

  await expect(drawer).toContainText("Passphrase for the key ~/.ssh/id_ed25519");
  await expect(drawer).toContainText("SHA256:fixturePublicFingerprint");

  // No attempt counter: a passphrase carries neither `attempt` nor `max_attempts`, and a
  // page that invented a first attempt would be reporting something nobody said.
  await expect(drawer).not.toContainText("attempt 1 of");

  const secret = page.locator("[data-ouro-secret]");
  await expect(secret).toHaveAttribute("type", "password");
  await expect(secret).toBeFocused();

  const passphrase = "browser-fixture-passphrase-" + Date.now();
  await page.keyboard.type(passphrase);
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Ready to deploy" })).toBeVisible();
  await expect(page.locator("[data-ouro-secret]")).toHaveCount(0);
  expect(await page.content()).not.toContain(passphrase);
});

test("a finished operation changes what its row says", async ({ page }) => {
  await openDevices(page);

  const device = peer(1);
  const row = page.locator('[data-address="' + device.address + '"]');
  await expect(row).toContainText("not set up");

  await startAdd(page, device);
  await expect(page.getByRole("heading", { name: /First time connecting/ })).toBeVisible();

  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();

  // The operation is the freshest thing known about this device, and the row says so rather
  // than going back to reading as an untouched peer with an Add to fleet button.
  await expect(row).toContainText("waiting for you");
  await expect(row.getByRole("button", { name: "Add to fleet" })).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Continue" })).toBeVisible();
});

test("closing the drawer keeps the operation, and the address reopens it", async ({ page }) => {
  await openDevices(page);

  const device = peer(6);
  await startAdd(page, device);
  await expect(page.getByRole("heading", { name: /First time connecting/ })).toBeVisible();

  const url = new URL(page.url());
  const operation = url.searchParams.get("operation");
  expect(operation).toMatch(/^[0-9a-f]{16}$/);

  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.locator("#ouro-deploy")).toHaveCount(0);
  await expect(page).toHaveURL(/\/devices$/);

  // Reopened by id, from a fresh page load: the operation outlived the drawer, and the
  // prompt it left is answerable from this load rather than bound to the one that started it.
  await page.goto("/devices?operation=" + operation);
  await liveConnected(page);
  await expect(page.locator("#ouro-deploy")).toBeVisible();
  await expect(page.locator("[data-ouro-operation]")).toHaveText(operation);
  await expect(page.locator("[data-ouro-rebind]")).toHaveCount(0);
  await page.getByRole("button", { name: "Trust and continue" }).click();
  await expect(page.locator("[data-ouro-secret]")).toBeVisible();
});
