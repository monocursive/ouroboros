# Ouroboros website

The standalone Astro landing page for Ouroboros. Static HTML and CSS, with a small script for copying the install command. Fonts and artwork are served locally; there is no analytics or external runtime dependency.

## Develop

Use Node.js 22.12 or later (an Astro-supported even-numbered release).

```sh
cd website
npm ci
npm run dev
```

Open the local URL printed by Astro. For a production build:

```sh
npm run build
npm run preview
```

No server adapter or runtime environment variables are required. The site expects to be hosted at the domain root.

## Cloudflare Pages deployment

- Project: `ouroboros` (production branch: `main`).
- Production domain: [ouroboros.monocursive.com](https://ouroboros.monocursive.com).
- Pages domain: [ouroboros-84r.pages.dev](https://ouroboros-84r.pages.dev).
- Configuration: `wrangler.jsonc`; Astro's `site` sets the canonical production URL.

The Cloudflare-managed `monocursive.com` zone has a proxied CNAME from `ouroboros` to `ouroboros-84r.pages.dev`. The hostname is also registered as a custom domain on the Pages project; both are needed for routing and certificate activation.

Authenticate with `npx wrangler login` when needed, then run from `website/`:

```sh
npm run deploy
```

This builds the site and uploads only `dist/` to the production Pages project. It uses direct uploads; Git pushes do not deploy automatically. Wrangler is pinned in the lockfile. Keep credentials in Wrangler's local authentication store or the CI secret store.

After deploying, verify both the deployment URL returned by Wrangler and the custom domain. Inspect deployment history with `npx wrangler pages deployment list --project-name ouroboros`.

## Design

- [Editable Figma design — desktop and mobile](https://www.figma.com/design/2C57WOSrsIfE4TKVP6fE39?node-id=2-9)
- [Original approved logo](https://www.figma.com/design/5Eh2aEO6voPQjTXBb8aMRt?node-id=33-2)
- Palette: near-black `#0b0d0c`, ivory `#f2efe8`, muted green `#b5d8a5`.
- Typography: Manrope (Fontsource) for headlines and prose; [Departure Mono](https://departuremono.com/) by Helena Zhang for the command, release marker, and technical labels. Departure Mono is served from `public/fonts/` with its SIL Open Font License. Technical text uses 11px for the font's native pixel grid.
- Headline: “Keep the work alive.”
- Supporting line: “Your machines. One agent runtime.”

`public/brand/ouroboros.svg` is an unchanged copy of `../assets/logo/ouroboros-negative-360.svg`. The orbit SVGs are exported from this page's Figma design. The favicon reuses the approved app icon.

Figma's connected font service does not provide Departure Mono. Its technical labels use vector outlines drawn from the official font, with the original editable text retained as hidden sibling layers. The website uses real, selectable text with the local WOFF2 font.

## Content maintenance

### Social link previews

The homepage emits its title, description, canonical URL, Open Graph image metadata,
and X large-image card metadata in the static HTML, so crawlers do not need JavaScript.
The preview image is `public/social/ouroboros-preview-v1.png` (1200 × 630 PNG).
Its editable source is `design/social-preview.html`, which reuses the unchanged
brand SVGs, local Manrope and Departure Mono fonts, and the site's palette.

To update the artwork, install dependencies in both the repository root and
`website/`, run `npx playwright install chromium` at the repository root once,
then run `npm run social:render` from `website/`. Inspect the exported PNG before
building. The PNG is checked in; ordinary website builds do not require Playwright.
When replacing an already published image, increment its filename in the renderer
and homepage metadata so crawlers get a fresh image URL.

After deployment, check the page and image return HTTP 200 without authentication,
including requests with social crawler user agents. Existing shares may retain
cached previews; request a fresh scrape in the platform's inspection tool when
available. Metadata and fetch checks alone do not prove a platform has refreshed
its displayed card. See the [Open Graph specification](https://ogp.me/).

The recorded demos and screenshot downloads use `public/demos/`. The repository
README references those same files, so there is one copy to maintain. See the
[capture notes](public/demos/README.md) for source revision, verified behavior,
timing edits, and recovery/fleet limits. Use MP4 plus posters on the website;
GIFs are supplied for GitHub and other surfaces without native video controls.
Demo videos do not autoplay or preload their video data.

The install command in `src/pages/index.astro` points to the latest stable release. The release badge intentionally links to the specific announced version; update its text and URL together when announcing a new version. Capabilities and platform guidance link to the maintained repository documentation.

Keep release notes on the GitHub release page linked by the homepage badge. Deploy
an announcement only after the release's packages are published.

The Models & access section describes the native runtime's authentication contract, checked against `lib/ouroboros/provider/openai_auth.ex` and `lib/ouroboros/provider/native/model/req_llm.ex`: OpenAI supports ChatGPT OAuth or API keys; Anthropic uses API keys; xAI supports the local Grok coding subscription sign-in through `grok:` models or separately billed API keys through `xai:` models. Gemini, OpenRouter, and Ollama are additional configurable ReqLLM transports, rather than default catalogue lanes. Model families are listed without fixed versions because catalogue metadata does not guarantee availability for a particular account. These statements are source-verified, not a claim that every provider was exercised with a live account.

Plan and billing references: [Codex with a ChatGPT plan](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan), [Claude subscriptions and API billing](https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-do-i-have-to-pay-separately-to-use-the-claude-api-and-console), and [xAI API billing](https://docs.x.ai/console/billing). Recheck the native authentication contract before adding another subscription option.

Both the page and command remain readable without JavaScript. The copy button appears when its handler is ready; if clipboard access is unavailable, it selects the command and provides manual-copy instructions. Motion respects the system's reduced-motion setting.

The [positioning brief](design/ouroboros-compintel-2026-09-13.html) records the comparison with pi, oh-my-pi, and OpenCode behind the current copy. It distinguishes documented features from positioning inferences and includes the limits of each claim. Recheck its sources before reusing competitive claims; the public page describes Ouroboros directly.
