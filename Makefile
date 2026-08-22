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

.PHONY: help dev test bench-local golden release-tarball ouro fleet-e2e dist

help:
	@echo "make dev              start a runtime from this checkout and attach (ouro --dev)"
	@echo "make test             mix test, cargo test, cargo fmt --check, cargo clippy"
	@echo "make bench-local      the local eval corpus: no key, no network, no docker"
	@echo "make golden           regenerate the gateway fixtures and fail on drift"
	@echo "make release-tarball  MIX_ENV=prod mix release, printing the tarball path"
	@echo "make ouro             that tarball baked into tui/target/release/ouro"
	@echo "make fleet-e2e        build ouro, then exercise a hermetic 3-node TLS fleet"
	@echo "make dist             ouro, copied to dist/ouro-<version>-<target triple>"

dev:
	@echo "==> dev: Elixir deps if this checkout has none, then ouro --dev"
	@test -d deps || $(MIX) deps.get
	cd tui && $(CARGO) run -- --dev

# The Rust suite runs twice on purpose. `embed` is off by default so that iterating on the
# client never waits on a release, which also means the extractor is not compiled — and an
# extractor nobody compiled is an extractor nobody tested.
test:
	@echo "==> test: mix test, then cargo test/fmt/clippy with and without the embed feature"
	$(MIX) test
	cd tui && $(CARGO) test
	cd tui && $(CARGO) test --features embed
	cd tui && $(CARGO) fmt --check
	cd tui && $(CARGO) clippy --all-targets -- -D warnings
	cd tui && $(CARGO) clippy --all-targets --features embed -- -D warnings

# Deliberately not part of `make test`. The corpus spawns a real daemon and drives it
# through the real client, so it is minutes of wall clock and it needs both halves built;
# `make test` has to stay the thing you run constantly. CI gets it as a manual job
# (.github/workflows/bench-local.yml), not on every push. See docs/BENCHMARKS.md.
bench-local:
	@echo "==> bench-local: the local eval corpus (no model key, no network, no docker)"
	./bench/local/run.sh

# The fixtures are the seam between two toolchains that cannot call each other's tests, so
# a regeneration that changes bytes is a protocol change and has to be committed as one.
golden:
	@echo "==> golden: regenerating the gateway fixtures and failing on drift"
	$(MIX) ouroboros.gateway.golden
	git diff --exit-code test/support/gateway_golden

release-tarball:
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
