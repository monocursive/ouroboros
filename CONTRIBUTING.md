# Contributing

## Branches

- `dev` is the integration branch. Branch off `dev` and open pull requests against `dev`.
- `main` is release-only. It advances when a release is cut from `dev` and is where
  `v*` tags live. Nothing merges into `main` directly.

## Local test gate

`make test` is the local gate — formatting (`mix format`, `cargo fmt`), the
destructive-lifecycle script tests, the Elixir suite, and the Rust suite with both
feature sets plus clippy — not the whole of CI:

```sh
make test
```

CI also runs Dialyzer, the suites with `OUROBOROS_REQUIRE_WASM` (a missing helper fails
rather than skips), golden fixture drift, protocol-docs drift, browser journeys, the
packaged three-node fleet, and the Linux container proofs (wasm, forge, sandbox). Run
`make dialyzer` locally if you touched specs or types. If a Dialyzer failure looks
garbled locally, use the default formatter — see the note in `.github/workflows/ci.yml`.

## Golden fixtures

The gateway protocol fixtures in `test/support/gateway_golden` are shared between the
Elixir and Rust suites. If you change the gateway protocol, regenerate them and commit
the diff, or CI's drift check will fail:

```sh
make golden
```

## Releases (maintainers)

1. Bump `version` in `mix.exs` on `dev`.
2. Merge `dev` into `main` once CI is green.
3. Tag `vX.Y.Z` on `main` — the tag must match the Mix version exactly, or the release
   workflow refuses to build. The workflow publishes signed binaries for four targets;
   see `docs/DISTRIBUTION.md` for the signing key requirements.
