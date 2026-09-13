# Contributing

## Branches

- `dev` is the integration branch. Branch off `dev` and open pull requests against `dev`.
- `main` is release-only. It advances when a release is cut from `dev` and is where
  `v*` tags live. Nothing merges into `main` directly.

## Changelog

For changes users will notice, add a short entry under `Unreleased` in
[CHANGELOG.md](CHANGELOG.md) in the same pull request. Describe the resulting
behavior and any upgrade action. Group entries under `Added`, `Changed`, `Fixed`,
`Removed`, `Deprecated`, or `Security` as needed; put migration and restart
instructions under `Upgrade notes`. Internal refactors and routine maintenance do
not need entries unless they change behavior for users.

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

For quick feedback when editing the release-packaging Makefile recipes:

```sh
make release-packaging-test
```

This focused check needs `make`, a POSIX `sh`, standard Unix utilities (including
`mktemp`), and a writable temporary directory (`$TMPDIR` or `/tmp`). It uses producer
stubs and does not build the product, so no Elixir/Erlang/Rust toolchains or fetched
dependencies are needed. `make test` remains the full local gate.

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

For a focused test that needs fresh durable runtime state, use
`scripts/test-isolated.sh mix test <test-path>`. It creates and removes only its own
private data leaf under `tmp/test-runtime`; it preserves the caller's HOME and
Erlang settings. It does not replace the ordinary in-memory `mix test` gate.

When an owned private test runner already supplies a fresh HOME and a loopback-only
EPMD, use `scripts/test-isolated.sh --loopback-peers mix test <test-path>` if the
machine's short hostname resolves outside loopback. The opt-in creates a private
`ERL_INETRC` mapping that hostname to `127.0.0.1` and binds the test VM and inherited
OS peers' distribution listeners to loopback. Canonical distributed assertions
remain unchanged; no machine DNS, hosts files, or global EPMD settings are changed.
The caller must supply `ERL_EPMD_ADDRESS=127.0.0.1` and a valid private
`ERL_EPMD_PORT` other than the default 4369 or reserved 65358, and retains ownership
of mapper startup/cleanup and private HOME. The wrapper does not read or copy
credentials and does not discover or claim ownership of an existing mapper.

This mode refuses an existing `ERL_INETRC` and nonempty `ERL_AFLAGS`, `ERL_FLAGS`,
`ERL_ZFLAGS`, or `ELIXIR_ERL_OPTIONS`: arbitrary Erlang options may contradict its
loopback interface, so it fails instead of replacing caller configuration. These
restrictions apply only to `--loopback-peers`. Validate the wrapper without starting
a VM or mapper with `sh scripts/test-isolated-test.sh`.

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

1. Set the same version in `mix.exs`, `tui/Cargo.toml`, and the `ouro` package entry
   in `tui/Cargo.lock`. Finalize the changelog entry with the release version and
   date, keep an `Unreleased` section for subsequent work, and update its comparison
   link to start at the new tag. Land the changes on `dev`.
2. Merge `dev` into `main` once CI is green.
3. Push an annotated `vX.Y.Z` tag on the reviewed `main` commit. The tag must match
   the version in all three files. GitHub Actions runs CI, builds and smoke-tests
   native binaries for macOS and GNU/Linux on ARM64 and x86-64, then publishes the
   complete release with the installer and checksums.

See [the release guide](docs/RELEASING.md#cut-a-release) for validation commands,
prerelease tags, release retries, and compatibility notes.
