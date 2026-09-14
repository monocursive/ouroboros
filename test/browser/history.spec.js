const { test, expect } = require("@playwright/test");

test("complete reviews and older pages remain scrollable", async ({ page }) => {
  await page.goto("/auth");
  await page.getByLabel("Access token").fill("ouroboros-browser-test-token-000000000000");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.goto("/s/interactive/browser-history");
  await expect(page.locator("[data-phx-main]")).toHaveClass(/\bphx-connected\b/);

  const transcript = page.locator("#transcript");
  const cells = transcript.locator("[data-history-cell]");
  await expect(cells).toHaveCount(50);
  // This answer spans more than the old 128-event drawing and 2,000-event retention caps.
  await expect(transcript).toContainText("Review section 1.");
  await expect(transcript).toContainText("Review section 2100.");
  await expect.poll(() => transcript.evaluate(el =>
    el.scrollHeight - el.scrollTop - el.clientHeight)).toBeLessThan(2);

  const start = Number(await transcript.getAttribute("data-history-start"));
  // Capture the reading position synchronously with the scroll, before the server reply.
  const offset = await transcript.evaluate(el => {
    el.scrollTop = 0;
    return el.querySelector("[data-history-cell]").getBoundingClientRect().top -
      el.getBoundingClientRect().top;
  });
  await expect(cells).toHaveCount(100);
  await expect.poll(async () => Math.abs(await transcript.evaluate((el, index) =>
    el.querySelector(`[data-history-cell="${index}"]`).getBoundingClientRect().top -
      el.getBoundingClientRect().top, start) - offset)).toBeLessThan(2);

  await transcript.evaluate(el => { el.scrollTop = 0; });
  await expect(transcript).toHaveAttribute("data-history-start", "0");
  await expect(transcript.getByRole("button", { name: "Load earlier messages" })).toHaveCount(0);
  const indices = await cells.evaluateAll(els => els.map(el => Number(el.dataset.historyCell)));
  expect(indices).toEqual(Array.from({ length: indices.length }, (_, i) => i));
  await expect(transcript).toContainText("History message 1.");

  // A reload starts at the latest page again, without losing access to the beginning.
  await page.reload();
  await expect(cells).toHaveCount(50);
  await expect(transcript).toHaveAttribute("data-history-start", String(start));
  await expect.poll(() => transcript.evaluate(el =>
    el.scrollHeight - el.scrollTop - el.clientHeight)).toBeLessThan(2);
});

test("gap replay preserves the reader's message and scroll offset", async ({ page }, testInfo) => {
  await page.goto("/auth");
  await page.getByLabel("Access token").fill("ouroboros-browser-test-token-000000000000");
  await page.getByRole("button", { name: "Continue" }).click();
  const client = testInfo.project.name.startsWith("mobile") ? "mobile" : "desktop";
  await page.goto(`/s/interactive/browser-history-replay-${client}`);
  await expect(page.locator("[data-phx-main]")).toHaveClass(/\bphx-connected\b/);
  const transcript = page.locator("#transcript");
  await expect(transcript).toHaveAttribute("data-history-start", "41");
  await transcript.getByRole("button", { name: "Load earlier messages" }).click();
  await expect(transcript).toHaveAttribute("data-history-start", "0");
  await expect(page.locator("#cells-gap-21-0")).toHaveCount(1);
  expect(await transcript.locator("[data-history-cell]").evaluateAll(els =>
    els.map(el => Number(el.dataset.historyCell)))).toEqual(Array.from({ length: 91 }, (_, i) => i));
  await page.locator("#ouro-composer-input").fill("repair history");

  const offset = await transcript.evaluate(el => {
    const cell = el.querySelector("#cells-event-71-0");
    el.scrollTop += cell.getBoundingClientRect().top - el.getBoundingClientRect().top - 100;
    return cell.getBoundingClientRect().top - el.getBoundingClientRect().top;
  });
  await expect.poll(() => transcript.evaluate(el =>
    el.scrollHeight - el.scrollTop - el.clientHeight)).toBeGreaterThan(100);
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.locator("#cells-gap-21-0")).toHaveCount(0);
  await expect(page.locator("#cells-event-71-0")).toContainText("Replay message 71.");
  await expect.poll(async () => Math.abs(await transcript.evaluate(el =>
    el.querySelector("#cells-event-71-0").getBoundingClientRect().top -
      el.getBoundingClientRect().top) - offset)).toBeLessThan(2);
  expect(await transcript.locator("[data-history-cell]").evaluateAll(els =>
    els.map(el => el.id))).toEqual(Array.from({ length: 100 }, (_, i) => `cells-event-${i + 1}-0`));
});
