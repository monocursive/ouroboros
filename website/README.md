# Ukai website

The Astro site for [Ukai](https://ukai.sh), covering the standalone Linux
jail and the separate macOS VM preview.

```sh
cd website
npm ci
npm run dev
npm run build
```

The homepage is `src/pages/index.astro`. The guide and roadmap render the
repository's `docs/guide.md` and `docs/roadmap.md` directly, so those documents
have one source. The cormorant branding lives in `../assets/logo/`; run
`uv run ../assets/logo/export_assets.py` from this directory to regenerate
the website assets and favicons. Fonts are hosted locally. Current source links
and clone instructions target `dev`; published release links retain their
immutable tags.

`/install.sh` and `/release.pub` are the repository's root `install.sh` and
`crates/ukai-jail/dist/release.pub`, imported at build time, so the served
installer cannot drift from the reviewed one. Release links and versions come
from `crates/ukai-jail/dist/release.json`. Its `published_tag` fields retain
the immutable tags of the previews released before the rename; `tag_prefix`
is for newly assembled Ukai releases. Update `published_tag` when publishing.

The documentation layout generates its section index from Markdown headings.
`/guide.md` and `/roadmap.md` serve the exact source text. `/llms.txt` is a
short discovery index following the [llms.txt proposal](https://llmstxt.org/),
and `/llms-full.txt` combines the index and both documents for a single fetch.
These are static build outputs, with no API service or separate content copy.
The page toolbar lets readers open Markdown or copy its URL for an agent;
automatic discovery of `llms.txt` is not assumed.

After editing shared files under `docs/`, restart the development server if
its Markdown cache is stale. `npm run build` regenerates all formats.

The Cloudflare Pages project `ukai` serves `https://ukai.sh`. `npm run
deploy` publishes the built site and must only be used when publication is
requested. Local builds do not update the live website.

Keep current features, experiments, and plans distinct. Link support and
performance claims to the exact recorded builds; never use the archived
runtime's releases as the jail installer.
