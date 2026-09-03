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


.PHONY: help dev tui daemon daemon-stop daemon-restart web status stop reset logs computer-use computer-use-debug sandbox sandbox-linux-test wasm wasm-guest wasm-examples wasm-sdk-check wasm-sdk-cache test dialyzer bench-local golden protocol-docs release-tarball ouro fleet-e2e dist dist-linux dist-linux-clean dist-check

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
	@echo "make test             formatting, script checks, mix test, cargo test/fmt/clippy"
	@echo "make dialyzer         gradual mix dialyzer; PLTs live under _build/plts"
	@echo "make bench-local      the local eval corpus: no key, no network, no docker"
	@echo "make golden           regenerate the gateway fixtures and fail on drift"
	@echo "make protocol-docs    regenerate docs/PROTOCOL.md and fail on drift"
	@echo "make release-tarball  MIX_ENV=prod mix release, printing the tarball path"
	@echo "make ouro             that tarball baked into tui/target/release/ouro"
	@echo "make fleet-e2e        build ouro, then exercise a hermetic 3-node TLS fleet"
	@echo "make dist             ouro, copied to dist/ouro-<version>-<target triple>"
	@echo "make dist-linux       the same, for x86_64-unknown-linux-gnu, built in Docker"
	@echo "make dist-linux-clean drop the dist-linux image and its cache volumes"
	@echo "make dist-check       install.sh against a local fixture; release.yml structure"
	@echo "make computer-use     build ouro-computer-use into priv/computer-use/"
	@echo "make sandbox          build ouro-sandbox into priv/sandbox/ (Linux sandbox helper)"
	@echo "make sandbox-linux-test  prove the sandbox helper enforces, in a Linux container"
	@echo "make wasm             build ouro-wasm into priv/wasm/ (WebAssembly containment helper)"
	@echo "make wasm-guest       build the lane-W acceptance guest into test/support/wasm/echo.wasm"
	@echo "make wasm-examples    build the guest SDK's worked components (counter, deny-writes, …)"
	@echo "make wasm-sdk-check   the guest SDK's own gates: fmt, tests, clippy, wasm32 build"
	@echo "make wasm-sdk-cache   warm this node's cargo cache with exactly the SDK's dependencies"

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

computer-use:
	@echo "==> computer-use: release helper into priv/computer-use/"
	cd tui && $(CARGO) build --release -p ouro-computer-use
	mkdir -p priv/computer-use
	cp tui/target/release/ouro-computer-use priv/computer-use/ouro-computer-use
	chmod 0755 priv/computer-use/ouro-computer-use
	@for env in dev test prod; do \
	  dest="_build/$$env/lib/ouroboros/priv/computer-use"; \
	  if [ -d "_build/$$env/lib/ouroboros/priv" ]; then \
	    mkdir -p "$$dest"; \
	    cp priv/computer-use/ouro-computer-use "$$dest/ouro-computer-use"; \
	    chmod 0755 "$$dest/ouro-computer-use"; \
	  fi; \
	done

# The sandbox helper only enforces on Linux, so building it on a Mac produces a binary
# whose `doctor` reports `"usable": false` and which `Sandbox.Helper.probe/1` therefore
# declines to select. That is deliberate: the target stays runnable everywhere so the
# install path is exercised on the machine the code is written on, and detection falls
# through to sandbox-exec exactly as it would with no helper at all.
sandbox:
	@echo "==> sandbox: release helper into priv/sandbox/"
	cd tui && $(CARGO) build --release -p ouro-sandbox
	mkdir -p priv/sandbox
	cp tui/target/release/ouro-sandbox priv/sandbox/ouro-sandbox
	chmod 0755 priv/sandbox/ouro-sandbox
	@for env in dev test prod; do \
	  dest="_build/$$env/lib/ouroboros/priv/sandbox"; \
	  if [ -d "_build/$$env/lib/ouroboros/priv" ]; then \
	    mkdir -p "$$dest"; \
	    cp priv/sandbox/ouro-sandbox "$$dest/ouro-sandbox"; \
	    chmod 0755 "$$dest/ouro-sandbox"; \
	  fi; \
	done
	@echo "==> sandbox: what this build can enforce here"
	@priv/sandbox/ouro-sandbox doctor

# The Linux enforcement proof, reproducible from a Mac. The helper's unit tests run
# anywhere; `tui/sandbox/tests/linux_enforcement.rs` only means something on a kernel with
# Landlock, and user namespaces need a privileged container to be creatable at all.
sandbox-linux-test:
	@echo "==> sandbox-linux-test: enforcement suite in a privileged Linux container"
	scripts/sandbox-linux-test.sh

# The WebAssembly containment helper. Unlike the sandbox helper this one enforces the same on
# every platform — the boundary is wasmtime's linker, not a kernel feature — so there is no
# per-OS caveat here. `ouro-wasm` carries a wasmtime, which needs a newer Rust than the rest of
# this workspace; see the rust-version note in tui/wasm/Cargo.toml.
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
# CARGO_HOME= names a node-local cache instead of the operator's own:
#   make wasm-sdk-cache CARGO_HOME=/var/lib/ouroboros/cargo
wasm-sdk-cache:
	@echo "==> wasm-sdk-cache: warming $${CARGO_HOME:-$$HOME/.cargo} with the SDK's dependency set"
	cd tui/wasm/guest && $(CARGO) fetch --locked
	@echo "==> wasm-sdk-cache: crates now cached"
	@ls "$${CARGO_HOME:-$$HOME/.cargo}/registry/cache" >/dev/null 2>&1 && \
	  find "$${CARGO_HOME:-$$HOME/.cargo}/registry/cache" -name '*.crate' | wc -l

computer-use-debug:
	@echo "==> computer-use-debug: debug helper into priv/computer-use/"
	cd tui && $(CARGO) build -p ouro-computer-use
	mkdir -p priv/computer-use
	cp tui/target/debug/ouro-computer-use priv/computer-use/ouro-computer-use
	chmod 0755 priv/computer-use/ouro-computer-use
	@for env in dev test prod; do \
	  dest="_build/$$env/lib/ouroboros/priv/computer-use"; \
	  if [ -d "_build/$$env/lib/ouroboros/priv" ]; then \
	    mkdir -p "$$dest"; \
	    cp priv/computer-use/ouro-computer-use "$$dest/ouro-computer-use"; \
	    chmod 0755 "$$dest/ouro-computer-use"; \
	  fi; \
	done



# The Rust suite runs twice on purpose. `embed` is off by default so that iterating on the
# client never waits on a release, which also means the extractor is not compiled — and an
# extractor nobody compiled is an extractor nobody tested.
test:
	@echo "==> test: formatting and scripts, then mix and Rust with both feature sets"
	$(MIX) format --check-formatted
	sh scripts/test-dev.sh
	SHELL="$(SHELL)" $(MIX) test
	cd tui && $(CARGO) test
	cd tui && $(CARGO) test --features embed
	cd tui && $(CARGO) fmt --check
	cd tui && $(CARGO) clippy --all-targets -- -D warnings
	cd tui && $(CARGO) clippy --all-targets --features embed -- -D warnings

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

# Deliberately not part of `make test`, for the same reason `fleet-e2e` is not: it needs
# tools `make test` must not require. The install.sh half needs only `sh` and a sha256
# tool and would be safe there; the release.yml half needs a YAML parser (python3 with
# PyYAML, or ruby), and a release whose four native runners fail because one of them lacks
# PyYAML is a worse outcome than a check somebody has to type. See docs/DISTRIBUTION.md §7.
dist-check:
	@echo "==> dist-check: install.sh against a local fixture release, then release.yml"
	sh scripts/test-install.sh
	sh scripts/check-release-workflow.sh

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

release-tarball: computer-use sandbox wasm
	@echo "==> release-tarball: MIX_ENV=prod mix release"
	MIX_ENV=prod $(MIX) release --overwrite
	@ls _build/prod/$(RELEASE)-*.tar.gz

# ERTS is not cross-compiled: this bakes the release built on *this* machine into a client
# for this machine. A binary for another OS or architecture is built there, which is what
# the release workflow's matrix is for.
ouro: release-tarball
	@echo "==> ouro: baking that tarball into tui/target/release/ouro"
	tarball="$$PWD/$$(ls _build/prod/$(RELEASE)-*.tar.gz | head -1)"; \
	cd tui && OUROBOROS_RELEASE_TARBALL="$$tarball" $(CARGO) build --release --features embed
	@ls -l tui/target/release/ouro

# Deliberately not part of `make test`: this builds a packaged release and repeatedly
# boots three real BEAM nodes. The script isolates HOME, data, ports, names, and cleanup.
fleet-e2e: ouro
	@echo "==> fleet-e2e: packaged three-node TLS formation and recovery"
	OURO_E2E_BIN="$$PWD/tui/target/release/ouro" bash scripts/fleet-e2e.sh

dist: ouro
	@echo "==> dist: naming the binary for the platform it can actually run"
	@mkdir -p dist
	version=$$(ls _build/prod/$(RELEASE)-*.tar.gz | head -1 | sed -e 's|.*/$(RELEASE)-||' -e 's|\.tar\.gz$$||'); \
	triple=$$(rustc -vV | sed -n 's/^host: //p'); \
	cp tui/target/release/ouro "dist/ouro-$$version-$$triple"; \
	echo "dist/ouro-$$version-$$triple"

# The one place `dist` above cannot reach: a machine that is not the target. ERTS is not
# cross-compiled, so this does not cross-compile — it runs the identical `make dist` on an
# emulated x86-64 Linux, in a container pinned to the release runner's OTP, Elixir, and
# Rust. Slow, and honestly labelled: it is the development path that gives `ouro fleet add`
# something to copy to a Linux box, not the release path. See docs/DISTRIBUTION.md §8.
dist-linux:
	@echo "==> dist-linux: dist/ouro-<version>-x86_64-unknown-linux-gnu, via Docker"
	@sh scripts/dist-linux.sh

dist-linux-clean:
	@sh scripts/dist-linux.sh --clean
