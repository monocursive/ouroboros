# Contributing

## Branches

- `dev` is the integration branch. Branch off `dev` and open pull requests against `dev`.
- `main` is release-only. It advances when a release is cut from `dev` and is where
  `v*` tags live. Nothing merges into `main` directly.

## Local test gate

Start in a fresh checkout with the [source-build toolchains](docs/PREVIEW.md#obtain-and-build)
(Elixir 1.20, Erlang/OTP 29, Rust 1.95, `make`, Git and a native C/C++ toolchain).
Install Hex/Rebar through the normal Mix prompts if requested. Prepare dependencies
and the formatting/lint components before either test branch below:

```sh
rustup component add rustfmt clippy
mix deps.get
```

`make test` is the local gate — formatting (`mix format`, `cargo fmt`), the
destructive-lifecycle script tests, the Elixir suite, the integration boot gate
(`make boot-gate`: a data directory written before the core reduction, booted twenty
times against this tree), and the Rust suite with both feature sets plus clippy — not the
whole of CI:

```sh
make test
```

The ordinary gate permits explicitly reported missing-WASM skips. For a required
WASM run from a fresh checkout, build the documented inputs **before** enabling
the requirement (including the examples used by the self-policy tests):

```sh
rustup target add wasm32-wasip2
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
make wasm-sdk-cache CARGO_HOME="$CARGO_HOME"
make wasm wasm-guest wasm-examples
OUROBOROS_REQUIRE_WASM=1 OUROBOROS_WASM_HELPER="$PWD/priv/wasm/ouro-wasm" make test
```

The cache fetch uses the SDK's complete lock, including other platforms' packages,
in the same Cargo home the fixtures use; a host-only build may not fetch them all.
Bare `make wasm-sdk-cache` defaults to a node-local cache instead. Required-WASM
tests also need a usable OS sandbox: Seatbelt on macOS or working bubblewrap
mount/network namespaces on Linux. An installed but policy-refused backend is not
enough. Report the refusal; do not disable host security to make tests pass.

These are local generated outputs and public dependency downloads, not files to
copy from another developer's retained experiments. Ordinary
Mix tests use their in-memory baseline and create private durable fixtures as
needed; do not globally set `OUROBOROS_DATA_DIR` to run them against a daemon's
state. `make boot-gate` builds/selects its own process-identity helper. Do not
globally export `OUROBOROS_PROCESS_ID_HELPER` for unrelated unit tests: that enables
the real recovery-lock path in tests intended to exercise the in-memory seam.

CI also runs Dialyzer, the suites with `OUROBOROS_REQUIRE_WASM` (a missing helper fails
rather than skips), golden fixture drift, protocol-docs drift, browser journeys, and the
Linux container proof for the wasm suites under bubblewrap. Run `make dialyzer` locally
if you touched specs or types. Run the browser journeys locally if you touched anything
the web renders — they are the only test that drives the pages in a browser, and nothing
in `make test` does. Use Node 22 and its npm (the CI baseline), after the common
Mix setup above. Node is for browser tests, not production web assets:

```sh
npm ci && npx playwright install chromium   # once
npm run test:browser                        # about thirty seconds, both viewports
```

Linux also needs Chromium's host libraries. In an owned, disposable CI environment
the project uses `npx playwright install --with-deps chromium` instead of the
browser-only install. On a managed host, arrange those distro dependencies with
the operator first: `--with-deps` may invoke privileged system package installation;
these instructions do not authorize machine-wide changes.

If a Dialyzer failure looks garbled locally, use the
default formatter — see the note in `.github/workflows/ci.yml`.

`dialyzer.ignore-warnings` pins each accepted warning by file *and line*, so adding or
removing lines above a pinned one silently unpins it and the warning fires again: re-run
`mix dialyzer` and re-pin whenever you edit a file that has an entry, and never pipe its
output into `tail`, which hides the exit code.

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
3. Tag `vX.Y.Z` on `main` — the tag must match the Mix version exactly. There is no
   binary publication workflow: `make ouro` builds the client with its release embedded,
   on the machine that will run it (`docs/proposals/core.md` §3).
