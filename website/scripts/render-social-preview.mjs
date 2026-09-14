import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

// Uses the repository's existing Playwright dependency; website builds only
// need the checked-in PNG and do not launch a browser.
const artwork = new URL('../design/social-preview.html', import.meta.url);
const output = new URL('../public/social/ouroboros-preview-v1.png', import.meta.url);
const browser = await chromium.launch();

try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  await page.goto(artwork.href, { waitUntil: 'load' });
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.images].map((image) => image.decode()));
    if (!document.fonts.check('500 86px Manrope') || !document.fonts.check('14px "Departure Mono"')) {
      throw new Error('Social preview fonts did not load');
    }
  });
  await mkdir(new URL('../public/social/', import.meta.url), { recursive: true });
  await page.screenshot({ path: fileURLToPath(output), type: 'png' });
  console.log(`Exported 1200 × 630 social preview: ${fileURLToPath(output)}`);
} finally {
  await browser.close();
}
