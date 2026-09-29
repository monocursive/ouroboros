# Ouroboros website

The Astro site restored from `legacy:website/`, updated for the standalone
`ouro-jail`. The archived agent runtime, release links, and demo recordings
are not part of this site.

```sh
cd website
npm ci
npm run dev
npm run build
```

The homepage is `src/pages/index.astro`. The guide and roadmap render the
repository's `docs/guide.md` and `docs/roadmap.md` directly, so those documents
have one source. The shared layout and styles retain the archived site's
branding and locally hosted fonts.

The documentation layout generates its section index from Markdown headings.
`/guide.md` and `/roadmap.md` serve the exact source text. `/llms.txt` is a
short discovery index following the [llms.txt proposal](https://llmstxt.org/),
and `/llms-full.txt` combines the index and both documents for a single fetch.
These are static build outputs, with no API service or separate content copy.
The page toolbar lets readers open Markdown or copy its URL for an agent;
automatic discovery of `llms.txt` is not assumed.

After editing shared files under `docs/`, restart the development server if
its Markdown cache is stale. `npm run build` regenerates all formats.

The restored Cloudflare Pages configuration targets `ouroboros`. `npm run
deploy` publishes the built site and must only be used when publication is
requested. Local builds do not update the live website.

Keep current features, experiments, and plans distinct. Link support and
performance claims to the exact recorded builds; never use the archived
runtime's releases as the jail installer.
