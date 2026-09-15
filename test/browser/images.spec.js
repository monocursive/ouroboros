const { test, expect } = require("@playwright/test");
const path = require("node:path");
const fs = require("node:fs");
const token = "ouroboros-browser-test-token-000000000000";
const image = path.resolve(__dirname, "../support/images/two-pixels.png");

test("images survive refresh, arrive with the first message, and render in reopened history", async ({ page }, info) => {
  const root = path.resolve(__dirname, "../../_build/playwright-workspace");
  const workspace = fs.mkdtempSync(path.join(root, "images-"));
  try {
    await page.goto(`/auth?${new URLSearchParams({ token, workspace })}`);
    await expect(page.locator("[data-attach]")).toBeEnabled();
    await page.locator("[data-image-picker]").setInputFiles(image);
    await expect(page.locator(".ouro-image-tray")).toContainText("2 × 1");
    await page.reload();
    await expect(page.locator(".ouro-image-tray")).toContainText("2 × 1");
    const firstDraft = await page.locator('[name="images_draft"]').inputValue();
    await page.getByRole("button", { name: "Start session", exact: true }).click();
    await expect(page).toHaveURL(/\/s\/interactive\//);
    const transcript = page.getByRole("log", {name: "Session transcript"});
    await expect(transcript).toContainText("Received 1 image(s)");
    await expect(transcript.locator("img")).toHaveCount(1);
    await expect.poll(() => transcript.locator("img").evaluate(img => img.complete && img.naturalWidth === 2)).toBe(true);
    await page.reload();
    await expect(transcript).toContainText("two-pixels.png");
    await transcript.locator("[data-image-preview]").click();
    await expect(page.locator("dialog.ouro-image-preview")).toBeVisible();
    await page.getByRole("button", {name: "Close image"}).click();
    await expect(page.locator("[data-attach]")).toBeEnabled();
    // Mixed clipboard text enters once; the image remains a separate attachment.
    await page.locator("#ouro-composer-input").evaluate(async (el, b64) => {
      const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const data = new DataTransfer();
      data.items.add(new File([bytes], "pasted.png", {type: "image/png"}));
      data.setData("text/plain", "inspect these pixels");
      el.dispatchEvent(new ClipboardEvent("paste", {clipboardData: data, bubbles: true, cancelable: true}));
    }, fs.readFileSync(image).toString("base64"));
    await expect(page.locator("#ouro-composer-input")).toHaveValue("inspect these pixels");
    await expect(page.locator("#image-draft .ouro-image-tray")).toContainText("2 × 1");
    const textareaWidth = await page.locator("#ouro-composer-input").evaluate(el => el.getBoundingClientRect().width);
    const composerWidth = await page.locator(".ouro-composer-box").evaluate(el => el.getBoundingClientRect().width);
    expect(textareaWidth).toBeGreaterThan(composerWidth * 0.85);
    await page.locator("[data-ouro-send]").click();
    await expect(transcript.locator("img")).toHaveCount(2);
    await expect(page.locator("#image-draft .ouro-image-card")).toHaveCount(0);
    await page.screenshot({path: path.join(info.outputDir, "images.png"), fullPage: true});
    // A retained image from the first task must not contaminate another initial draft
    // in the same authenticated tab, even after navigating through a full page load.
    const secondWorkspace = path.join(workspace, "second");
    fs.mkdirSync(secondWorkspace);
    await page.goto("/new");
    await page.locator("#workspace").fill(secondWorkspace);
    await expect(page.locator("[data-attach]")).toBeEnabled();
    await page.locator("[data-image-picker]").setInputFiles(image);
    await expect(page.locator(".ouro-image-tray")).toContainText("2 × 1");
    expect(await page.locator('[name="images_draft"]').inputValue()).not.toBe(firstDraft);
    await page.getByRole("button", { name: "Start session", exact: true }).click();
    await expect(page).toHaveURL(/\/s\/interactive\//);
    await expect(page.getByRole("log", {name: "Session transcript"})).toContainText("Received 1 image(s)");
  } finally { fs.rmSync(workspace, {recursive: true, force: true}); }
});

test("a failed image blocks sending and can be removed without losing text", async ({ page }) => {
  const workspace = path.resolve(__dirname, "../../_build/playwright-workspace");
  await page.goto(`/auth?${new URLSearchParams({ token, workspace })}`);
  await expect(page.locator("[data-attach]")).toBeEnabled();
  await page.locator("#initial-message").fill("retain this draft");
  await page.locator("[data-image-picker]").setInputFiles({name: "corrupt.png", mimeType: "image/png", buffer: Buffer.from("invalid pixels")});
  await expect(page.locator(".ouro-image-tray")).toContainText("failed");
  await page.getByRole("button", { name: "Start session", exact: true }).click();
  await expect(page).toHaveURL(/\/new/);
  await expect(page.locator("#initial-message")).toHaveValue("retain this draft");
  await page.getByRole("button", {name: "Remove corrupt.png"}).click();
  await expect(page.locator(".ouro-image-card")).toHaveCount(0);
});

test("palette Send preserves images and blocks pending or failed uploads", async ({ page }) => {
  const root = path.resolve(__dirname, "../../_build/playwright-workspace");
  const workspace = fs.mkdtempSync(path.join(root, "palette-images-"));
  try {
    await page.goto(`/auth?${new URLSearchParams({ token, workspace })}`);
    await expect(page.locator("[data-attach]")).toBeEnabled();
    await page.getByRole("button", { name: "Start session", exact: true }).click();
    await expect(page).toHaveURL(/\/s\/interactive\//);
    await expect(page.locator("[data-attach]")).toBeEnabled();
    const composer = page.locator("#ouro-composer-input");
    const tray = page.locator("#image-draft .ouro-image-tray");
    const transcript = page.getByRole("log", { name: "Session transcript" });
    async function paletteSend() {
      await page.getByRole("button", { name: /Commands/ }).click();
      await page.locator('[phx-value-id="turn.send"]').click();
      await expect(page.locator("#ouro-palette")).toHaveCount(0);
    }

    // Hold real file acquisition so the pending state cannot race the palette click.
    await page.evaluate(() => {
      const read = File.prototype.arrayBuffer;
      File.prototype.arrayBuffer = function () {
        if (this.name !== "held.png") return read.call(this);
        return new Promise(resolve => {
          window.releaseImageRead = () => resolve(read.call(this));
        });
      };
    });
    await composer.fill("describe these pixels");
    await page.locator("[data-image-picker]").setInputFiles({
      name: "held.png", mimeType: "image/png", buffer: fs.readFileSync(image)
    });
    await expect(tray).toContainText("uploading");
    await paletteSend();
    await expect(composer).toHaveValue("describe these pixels");
    await expect(transcript).not.toContainText("describe these pixels");

    await page.evaluate(() => window.releaseImageRead());
    await expect(tray).toContainText("2 × 1");
    await paletteSend();
    await expect(transcript).toContainText("Received 1 image(s)");
    await expect(transcript).toContainText("describe these pixels");
    await expect(transcript.locator("img")).toHaveCount(1);
    await expect(tray.locator(".ouro-image-card")).toHaveCount(0);
    await expect(composer).toHaveValue("");

    await composer.fill("retain the failed draft");
    await page.locator("[data-image-picker]").setInputFiles({
      name: "corrupt.png", mimeType: "image/png", buffer: Buffer.from("invalid pixels")
    });
    await expect(tray).toContainText("failed");
    await paletteSend();
    await expect(composer).toHaveValue("retain the failed draft");
    await expect(transcript).not.toContainText("retain the failed draft");
    await expect(tray).toContainText("corrupt.png");
  } finally { fs.rmSync(workspace, { recursive: true, force: true }); }
});
