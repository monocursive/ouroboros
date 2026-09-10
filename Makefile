# Ouroboros build verbs: one place that knows how the Elixir half and the Rust half fit
# together. `docs/TUI.md` §4 originally specified a justfile; this is the same verb list
# as plain make, so that building the client needs no build tool the repository does not
# already require.
#
# Versions and target triples are computed inside the recipes rather than in make
# variables, so nothing here runs a subprocess just to print the help text, and nothing
# depends on a GNU extension. The version of record is the name `mix release` gave the
# tarball — the release names the artifact, not this file.

MIX ?= mix
CARGO ?= cargo
RELEASE ?= ouroboros


.PHONY: help dev tui daemon daemon-stop daemon-restart web status stop reset logs wasm wasm-guest wasm-examples wasm-sdk-check wasm-sdk-cache wasm-linux-test wasm-skew-test test boot-gate dialyzer bench-local self-export golden protocol-docs release-tarball ouro bench-self improve-selftest

help:
	@echo "make dev              start a runtime from this checkout and attach (ouro --dev)"
	@echo "make tui              the same, under the name of the thing it opens"
	@echo "make daemon           start the dev runtime headless and leave it running"
	@echo "make daemon-restart   recompile, then swap the dev runtime onto the new code"
	@echo "make daemon-stop      stop the dev runtime"
	@echo "make web              open the checkout runtime's browser surface in a browser"
	@echo "make status           what is running, on which port, and whether it is stale"
	@echo "make stop             everything down: daemon, and any stray daemons"
	@echo "make reset            stop everything, then empty the dev data dir (oauth.json kept)"
	@echo "make logs             follow the dev runtime's log"
	@echo "make test             formatting, script checks, mix test, the boot gate, cargo test/fmt/clippy"
	@echo "make boot-gate        pre-reduction and pre-J2 data booted against this tree, 10x per mode"
	@echo "make dialyzer         gradual mix dialyzer; PLTs live under _build/plts"
	@echo "make bench-local      the local eval corpus: no key, no network, no docker"
	@echo "make self-export      write this node's promoted policy + record into priv/self/"
	@echo "make bench-self       the self corpus selftest: no key, no network, no spend"
	@echo "make improve-selftest the improve loop's selftest: no key, no network, no spend"
	@echo "make golden           regenerate the gateway fixtures and fail on drift"
	@echo "make protocol-docs    regenerate docs/PROTOCOL.md and fail on drift"
	@echo "make release-tarball  MIX_ENV=prod mix release, printing the tarball path"
	@echo "make ouro             that tarball baked into tui/target/release/ouro"
	@echo "make wasm-linux-test     prove the wasm suites under bubblewrap, in a Linux container"
	@echo "make wasm             build ouro-wasm into priv/wasm/ (WebAssembly containment helper)"
	@echo "make wasm-guest       build the lane-W acceptance guest into test/support/wasm/echo.wasm"
	@echo "make wasm-examples    build the guest SDK's worked components (counter, deny-writes, …)"
	@echo "make wasm-sdk-check   the guest SDK's own gates: fmt, tests, clippy, wasm32 build"
	@echo "make wasm-sdk-cache   warm this node's cargo cache with exactly the SDK's dependencies"
	@echo "make wasm-skew-test   prove the precompiled skew refusals with two real toolchains"

dev:
	@echo "==> dev: Elixir deps if this checkout has none, then ouro --dev"
	@test -d deps || $(MIX) deps.get
	cd tui && $(CARGO) run -- --dev

tui: dev

# The daemon/web/status/stop family is one script, so the knowledge of where the dev
# gateway publishes, how staleness is judged, and what counts as a stray daemon has a
# single home. See scripts/dev.sh.
daemon:
	@sh scripts/dev.sh daemon

daemon-stop:
	@sh scripts/dev.sh daemon-stop

daemon-restart:
	@sh scripts/dev.sh daemon-restart

web:
	@sh scripts/dev.sh web

status:
	@sh scripts/dev.sh status

stop:
	@sh scripts/dev.sh stop-all

reset:
	@sh scripts/dev.sh reset

logs:
	@sh scripts/dev.sh logs

# The WebAssembly containment helper, and the only helper this repository builds. It
# enforces the same on every platform — the boundary is wasmtime's linker, not a kernel
# feature — so there is no per-OS caveat here. `ouro-wasm` carries a wasmtime, which needs a
# newer Rust than the rest of this workspace; see the rust-version note in tui/wasm/Cargo.toml.
wasm:
	@echo "==> wasm: release helper into priv/wasm/"
	cd tui && $(CARGO) build --release -p ouro-wasm
	mkdir -p priv/wasm
	cp tui/target/release/ouro-wasm priv/wasm/ouro-wasm
	chmod 0755 priv/wasm/ouro-wasm
	@for env in dev test prod; do \
	  dest="_build/$$env/lib/ouroboros/priv/wasm"; \
	  if [ -d "_build/$$env/lib/ouroboros/priv" ]; then \
	    mkdir -p "$$dest"; \
	    cp priv/wasm/ouro-wasm "$$dest/ouro-wasm"; \
	    chmod 0755 "$$dest/ouro-wasm"; \
	  fi; \
	done
	@echo "==> wasm: what this build can contain"
	@priv/wasm/ouro-wasm doctor

# The lane-W acceptance guest: a real component, built by a real toolchain, from the world at
# tui/wasm/wit/capability.wit — and, since W9, on the guest SDK at tui/wasm/guest, which it
# reaches by path dependency. It is a *test fixture* and deliberately not a `release-tarball`
# prerequisite — nothing a node runs needs it. Its own workspace and its own lockfile, so it
# can never enter `ouro`'s dependency graph, and its output is gitignored like every other
# built binary here. Needs one toolchain addition: `rustup target add wasm32-wasip2`.
wasm-guest:
	@echo "==> wasm-guest: release component into test/support/wasm/echo.wasm"
	cd test/support/wasm/echo-guest && $(CARGO) build --release --target wasm32-wasip2
	cp test/support/wasm/echo-guest/target/wasm32-wasip2/release/ouroboros_echo_guest.wasm \
	  test/support/wasm/echo.wasm
	@echo "==> wasm-guest: what it declares"
	@ls -l test/support/wasm/echo.wasm

# The SDK's worked components, one per seam plus the verdict fixture. Each is a standalone
# workspace built with a plain `cargo build`, because that is the claim: an author writes their
# own logic and one macro call, and what comes out is a component in this world whose whole
# authority is `log`. `tui/wasm/tests/sdk.rs` builds these same four and puts that claim to the
# real helper; `test/wasm/sdk_acceptance_test.exs` runs the built artifacts through
# `provider/native/hooks.ex` and asserts the decision the node reaches — which is why this
# target is a prerequisite of that suite rather than a convenience.
wasm-examples:
	@echo "==> wasm-examples: the guest SDK's worked components"
	cd tui/wasm/guest/examples/counter && $(CARGO) build --release --target wasm32-wasip2
	cd tui/wasm/guest/examples/deny-writes && $(CARGO) build --release --target wasm32-wasip2
	cd tui/wasm/guest/examples/lintcheck && $(CARGO) build --release --target wasm32-wasip2
	cd tui/wasm/guest/examples/verdicts && $(CARGO) build --release --target wasm32-wasip2
	# W15. The fifth is the first in the *policy* world, so this line is also the standing
	# proof that one SDK builds both: `ouroboros:policy@0.1.0`, importing exactly `log`.
	cd tui/wasm/guest/examples/no-network-shell && $(CARGO) build --release --target wasm32-wasip2
	@echo "==> wasm-examples: what they declare"
	@ls -l tui/wasm/guest/examples/counter/target/wasm32-wasip2/release/counter.wasm \
	  tui/wasm/guest/examples/deny-writes/target/wasm32-wasip2/release/deny_writes.wasm \
	  tui/wasm/guest/examples/lintcheck/target/wasm32-wasip2/release/lintcheck.wasm \
	  tui/wasm/guest/examples/verdicts/target/wasm32-wasip2/release/verdicts.wasm \
	  tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm

# The SDK's own gates. Its own workspace means `make test`'s `cd tui && cargo …` never reaches
# it, so it gets a verb rather than being checked by nobody.
#
# Twice through clippy on purpose. The host pass is the only one that can lint the unit tests —
# `Describe`'s document and `Verdict`'s reply are checked there, on a target with a test
# harness — and the `wasm32-wasip2` pass is the build that actually ships. A lint that fires on
# one and not the other is exactly the kind of thing a single pass would miss.
wasm-sdk-check:
	@echo "==> wasm-sdk-check: the guest SDK's own gates"
	cd tui/wasm/guest && $(CARGO) fmt --check
	cd tui/wasm/guest && $(CARGO) test
	cd tui/wasm/guest && $(CARGO) clippy --all-targets -- -D warnings
	cd tui/wasm/guest && $(CARGO) clippy --target wasm32-wasip2 -- -D warnings
	cd tui/wasm/guest && $(CARGO) build --release --target wasm32-wasip2

# The registry cache a `:builder` node forges against (docs/WASM.md D19). `Ouroboros.Wasm.Forge`
# builds `--locked --offline` inside a sandbox with no network, so every crate the SDK's lock
# names has to already be in `$CARGO_HOME/registry/cache` before a forge starts; a cache that is
# missing one is a refusal naming it, not a fetch. `cargo fetch --locked` in the SDK's own
# directory downloads exactly that set and nothing else — it is the SDK's lock that decides,
# which is the same lock the forge pins a submitted project to.
#
# It warms the node's OWN cache by default — `<data_dir>/wasm/cargo-home`, derived here
# exactly as `Ouroboros.DataDir` derives it — and not `~/.cargo`. That is the whole of D19's
# second half: a cargo home carries `config.toml`, `[build] rustc-wrapper` in it is a program
# cargo runs on every crate, and a developer's `~/.cargo` is a directory many things write
# to. The forge uses this path unless an operator names another one.
#
# CARGO_HOME= names a different cache, for a builder that keeps its own:
#   make wasm-sdk-cache CARGO_HOME=/var/lib/ouroboros/cargo
OURO_DATA_DIR := $(or $(OUROBOROS_DATA_DIR),$(if $(XDG_DATA_HOME),$(XDG_DATA_HOME)/ouroboros,$(HOME)/.local/share/ouroboros))
FORGE_CARGO_HOME := $(or $(CARGO_HOME),$(OURO_DATA_DIR)/wasm/cargo-home)

wasm-sdk-cache:
	@echo "==> wasm-sdk-cache: warming $(FORGE_CARGO_HOME) with the SDK's dependency set"
	mkdir -p "$(FORGE_CARGO_HOME)"
	cd tui/wasm/guest && CARGO_HOME="$(FORGE_CARGO_HOME)" $(CARGO) fetch --locked
	@echo "==> wasm-sdk-cache: crates now cached"
	@find "$(FORGE_CARGO_HOME)/registry/cache" -name '*.crate' | wc -l

# Lane W under bubblewrap: the Linux backend, the one the hosted CI job runs every wasm
# suite under, and the one no Mac exercises. It is what found W16's merged-`/usr`
# namespace hole.
wasm-linux-test:
	@echo "==> wasm-linux-test: the wasm suites under bubblewrap on a Linux kernel"
	scripts/wasm-linux-test.sh

# W8's precompiled-artifact skew, with two real toolchains instead of a crafted header. Builds
# `ouro-wasm` on a Linux kernel and again at one other wasmtime, precompiles the acceptance
# guest with each, and offers both to this machine's own helper: each must be refused
# `precompiled_mismatch` naming both sides, and the source form must still load. The artifacts
# land in `_build/wasm-skew/`, which `test/wasm/skew_test.exs` reads.
wasm-skew-test:
	@echo "==> wasm-skew-test: a precompiled artifact from another toolchain, refused by name"
	scripts/wasm-skew-test.sh

# The Rust suite runs twice on purpose. `embed` is off by default so that iterating on the
# client never waits on a release, which also means the extractor is not compiled — and an
# extractor nobody compiled is an extractor nobody tested.
test:
	@echo "==> test: formatting and scripts, then mix, the boot gate, and Rust with both feature sets"
	$(MIX) format --check-formatted
	sh scripts/test-dev.sh
	SHELL="$(SHELL)" $(MIX) test
	$(MAKE) boot-gate
	cd tui && $(CARGO) test
	cd tui && $(CARGO) test --features embed
	cd tui && $(CARGO) fmt --check
	cd tui && $(CARGO) clippy --all-targets -- -D warnings
	cd tui && $(CARGO) clippy --all-targets --features embed -- -D warnings

# The integration gate of the core reduction (docs/proposals/core.md, "Status"): the data
# directory `dev` wrote at 3bc8887, holding every durable shape the reduction retired, booted
# against this tree ten times under interactive code loading and ten times with every module
# preloaded, each against a fresh copy, with every count compared against the record in
# test/support/integration_fixture/README.md. It needs an `ouro` binary for the
# process-incarnation helper (`make ouro`'s, or a debug build it makes itself) and it boots in
# the development environment, where that helper is required exactly as it is on a real node.
# The additional pre-J2 corpus exercises retired session structs under both loading modes.
boot-gate:
	@echo "==> boot-gate: the pre-reduction data directory, booted against this tree"
	MIX_ENV=dev $(MIX) compile
	sh scripts/fixture/boot_gate.sh
	sh scripts/fixture/j2_boot_gate.sh

# Deliberately not part of `make test`: the first run builds a PLT and even incremental
# runs are minutes, not the seconds `mix test` is supposed to stay. CI has its own job.
dialyzer:
	@echo "==> dialyzer: gradual success typing against the local PLT"
	$(MIX) dialyzer

# Deliberately not part of `make test`. The corpus spawns a real daemon and drives it
# through the real client, so it is minutes of wall clock and it needs both halves built;
# `make test` has to stay the thing you run constantly. CI gets it as a manual job
# (.github/workflows/bench-local.yml), not on every push. See docs/BENCHMARKS.md.
bench-local:
	@echo "==> bench-local: the local eval corpus (no model key, no network, no docker)"
	./bench/local/run.sh

# S4. What this installation learned, written into priv/self/ so the next one carries it:
# the promoted policy's signed bundle out of this node's store, the promotion record with
# its replay numbers, and the signer line the receiving operator has to trust before any of
# it deploys. The outer loop's pull request commits all three (docs/SELF.md §S4).
#
# It reads the running node's durable state, so it opens the data directory a second time.
# Stop the daemon first — `make daemon-stop` — or run it against a data directory nothing
# else is holding, with OUROBOROS_DATA_DIR.
self-export:
	@echo "==> self-export: the promoted policy and its record into priv/self/"
	@echo "    (stop the daemon first: this opens the same data directory, and refuses while one holds it)"
	$(MIX) ouroboros.self.export
# The $0 half of the self corpus: the verdict rule, every refusal, the extractor's gates,
# and the eight scripted agents that must not score — three of which are exploits an
# adversarial review used to make an earlier version of the grader say `pass`. Twenty
# minutes or so; the cheap half runs first. A *paid* run is `bench/self/run.sh --spend
# <usd>` and is never a make target, because a target is a thing people run without
# reading it. See docs/BENCHMARKS.md §5.
bench-self:
	@echo "==> bench-self: the self corpus selftest (no model key, no network, no spend)"
	./bench/self/selftest.sh
# Deliberately not part of `make test`, for the same reason as `bench-local`: it makes a
# dozen git worktrees, clones `_build` into each, and runs the gates inside them, which is
# minutes rather than seconds. It needs no model key, no network and no spend — the client
# is a shim. See bench/self/IMPROVE.md.
improve-selftest:
	@echo "==> improve-selftest: the outer loop against a shim client (no key, no spend)"
	./bench/self/improve-selftest.sh

# The fixtures are the seam between two toolchains that cannot call each other's tests, so
# a regeneration that changes bytes is a protocol change and has to be committed as one.
golden:
	@echo "==> golden: regenerating the gateway fixtures and failing on drift"
	$(MIX) ouroboros.gateway.golden
	git diff --exit-code test/support/gateway_golden

# `docs/PROTOCOL.md` is generated from the method table, the parameter contract, and the
# fixtures above — so it is regenerated after them, and in that order. A diff here is a
# protocol change and is committed as one, exactly like a fixture diff.
protocol-docs: golden
	@echo "==> protocol-docs: regenerating docs/PROTOCOL.md and failing on drift"
	$(MIX) ouroboros.protocol.docs
	git diff --exit-code docs/PROTOCOL.md

release-tarball: wasm
	@echo "==> release-tarball: MIX_ENV=prod mix release"
	MIX_ENV=prod $(MIX) release --overwrite
	@ls _build/prod/$(RELEASE)-*.tar.gz

# ERTS is not cross-compiled: this bakes the release built on *this* machine into a client
# for this machine. A binary for another OS or architecture is built there, on that
# machine, with the same target.
ouro: release-tarball
	@echo "==> ouro: baking that tarball into tui/target/release/ouro"
	tarball="$$PWD/$$(ls _build/prod/$(RELEASE)-*.tar.gz | head -1)"; \
	cd tui && OUROBOROS_RELEASE_TARBALL="$$tarball" $(CARGO) build --release --features embed
	@ls -l tui/target/release/ouro
