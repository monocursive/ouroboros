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


.PHONY: help dev tui daemon daemon-stop daemon-restart gui gui-stop status stop reset logs desktop-dev desktop-app computer-use computer-use-debug test dialyzer bench-local golden protocol-docs release-tarball ouro fleet-e2e dist dist-check

help:
	@echo "make dev              start a runtime from this checkout and attach (ouro --dev)"
	@echo "make tui              the same, under the name of the thing it opens"
	@echo "make daemon           start the dev runtime headless and leave it running"
	@echo "make daemon-restart   recompile, then swap the dev runtime onto the new code"
	@echo "make daemon-stop      stop the dev runtime"
	@echo "make gui              build the desktop app and (re)launch it against the checkout"
	@echo "make gui-stop         quit the desktop app"
	@echo "make status           what is running, on which port, and whether it is stale"
	@echo "make stop             everything down: app, daemon, and any stray daemons"
	@echo "make reset            stop everything, then empty the dev data dir (oauth.json kept)"
	@echo "make logs             follow the dev runtime's log"
	@echo "make desktop-dev      build a local macOS Ouroboros.app using this checkout"
	@echo "make desktop-app      build a release macOS Ouroboros.app with embedded runtime"
	@echo "make test             formatting, script checks, mix test, cargo test/fmt/clippy"
	@echo "make dialyzer         gradual mix dialyzer; PLTs live under _build/plts"
	@echo "make bench-local      the local eval corpus: no key, no network, no docker"
	@echo "make golden           regenerate the gateway fixtures and fail on drift"
	@echo "make protocol-docs    regenerate docs/PROTOCOL.md and fail on drift"
	@echo "make release-tarball  MIX_ENV=prod mix release, printing the tarball path"
	@echo "make ouro             that tarball baked into tui/target/release/ouro"
	@echo "make fleet-e2e        build ouro, then exercise a hermetic 3-node TLS fleet"
	@echo "make dist             ouro, copied to dist/ouro-<version>-<target triple>"
	@echo "make dist-check       install.sh against a local fixture; release.yml structure"
	@echo "make computer-use     build ouro-computer-use into priv/computer-use/"

dev:
	@echo "==> dev: Elixir deps if this checkout has none, then ouro --dev"
	@test -d deps || $(MIX) deps.get
	cd tui && $(CARGO) run -- --dev

tui: dev

# The daemon/gui/status/stop family is one script, so the knowledge of where the dev
# gateway publishes, how staleness is judged, and what counts as a stray daemon has a
# single home. See scripts/dev.sh.
daemon:
	@sh scripts/dev.sh daemon

daemon-stop:
	@sh scripts/dev.sh daemon-stop

daemon-restart:
	@sh scripts/dev.sh daemon-restart

gui:
	@sh scripts/dev.sh gui

gui-stop:
	@sh scripts/dev.sh gui-stop

status:
	@sh scripts/dev.sh status

stop:
	@sh scripts/dev.sh stop-all

reset:
	@sh scripts/dev.sh reset

logs:
	@sh scripts/dev.sh logs

desktop-dev: computer-use-debug
	@echo "==> desktop-dev: building the native client and its lifecycle helper"
	cd tui && $(CARGO) build --features desktop --bin ouro --bin ouro-desktop
	./scripts/bundle-macos-desktop.sh debug

desktop-app: computer-use release-tarball
	@echo "==> desktop-app: embedding the runtime in both macOS app executables"
	tarball="$$PWD/$$(ls _build/prod/$(RELEASE)-*.tar.gz | head -1)"; \
	cd tui && OUROBOROS_RELEASE_TARBALL="$$tarball" $(CARGO) build --release --features "embed desktop" --bin ouro --bin ouro-desktop
	./scripts/bundle-macos-desktop.sh release

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

release-tarball: computer-use
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
