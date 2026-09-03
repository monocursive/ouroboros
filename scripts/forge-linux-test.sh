#!/bin/sh
# The lane-W forge's Linux half, proved on a Linux kernel from a Mac.
#
# `Ouroboros.Wasm.Forge` builds a component inside `Ouroboros.Provider.Native.Sandbox`'s
# builder policy (docs/WASM.md D18), and that policy has two forms: a Seatbelt profile on
# macOS and a bubblewrap namespace on Linux. The macOS form is exercised by every `mix test`
# on a developer's machine. The Linux form was written blind, shipped as "unverified", and
# was wrong in exactly the way writing a namespace blind is wrong: `/dev` was re-bound
# read-only over bubblewrap's own `--dev`, so the first thing a build did was fail to open
# `/dev/null`.
#
# This runs the forge's own suites against a real kernel. `--privileged` is what allows
# `unshare(CLONE_NEWUSER)`; Docker's default seccomp profile denies it, which is a fact
# about the container and not about bubblewrap needing privilege — see
# `scripts/sandbox-linux-test.sh`, which says the same thing for the same reason.
#
# What the container has to build before it can test: the helper (`make wasm`) and the
# acceptance guest and examples (`make wasm-guest`, `make wasm-examples`), because the ones
# in a Mac checkout are Mach-O and a `wasm32-wasip2` component built for a different host
# toolchain is not something to reuse on faith. Then a warmed cargo cache, because the forge
# builds `--offline` (D19).
#
# Usage: scripts/forge-linux-test.sh [extra mix test args]

set -eu

IMAGE="${OURO_FORGE_TEST_IMAGE:-hexpm/elixir:1.20.2-erlang-29.0.5-ubuntu-noble-20260730.1}"
RUST_VERSION="${OURO_FORGE_TEST_RUST:-1.95.0}"
VOLUME_CARGO=ouro-forge-cargo
VOLUME_RUSTUP=ouro-forge-rustup
VOLUME_BUILD=ouro-forge-build
VOLUME_DEPS=ouro-forge-deps
# One volume per directory a build writes into the checkout. The repository is bind-mounted
# so an edit on the Mac is visible here immediately, and that cuts both ways: without these,
# the container's ELF helper would land on top of the Mach-O one this Mac's own `mix test`
# uses, and cargo would rebuild every crate on every switch between the two hosts.
VOLUME_HELPER=ouro-forge-helper
VOLUME_PRIV_NATIVE=ouro-forge-priv-native
VOLUME_TUI_TARGET=ouro-forge-tui-target
VOLUME_GUEST_TARGET=ouro-forge-guest-target
VOLUME_SDK_TARGET=ouro-forge-sdk-target
VOLUME_EXAMPLES=ouro-forge-examples

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v docker >/dev/null 2>&1; then
  echo "forge-linux-test: docker is not on PATH." >&2
  echo "  On a Linux host with bubblewrap and rustup you can instead run:" >&2
  echo "    OUROBOROS_REQUIRE_WASM=1 mix test test/wasm/forge_test.exs" >&2
  exit 1
fi

EXAMPLES="counter deny-writes lintcheck verdicts no-network-shell"

for volume in "$VOLUME_CARGO" "$VOLUME_RUSTUP" "$VOLUME_BUILD" "$VOLUME_DEPS" \
  "$VOLUME_HELPER" "$VOLUME_PRIV_NATIVE" "$VOLUME_TUI_TARGET" "$VOLUME_GUEST_TARGET" \
  "$VOLUME_SDK_TARGET"; do
  docker volume create "$volume" >/dev/null
done

example_mounts=""
for example in $EXAMPLES; do
  docker volume create "$VOLUME_EXAMPLES-$example" >/dev/null
  example_mounts="$example_mounts -v $VOLUME_EXAMPLES-$example:/src/tui/wasm/guest/examples/$example/target"
done

exec docker run --rm --privileged \
  -v "$root:/src" \
  -v "$VOLUME_CARGO:/cargo" \
  -v "$VOLUME_RUSTUP:/rustup" \
  -v "$VOLUME_BUILD:/src/_build" \
  -v "$VOLUME_DEPS:/src/deps" \
  -v "$root/deps:/host-deps:ro" \
  -v "$VOLUME_HELPER:/src/priv/wasm" \
  -v "$VOLUME_PRIV_NATIVE:/src/priv/native" \
  -v "$VOLUME_TUI_TARGET:/src/tui/target" \
  -v "$VOLUME_GUEST_TARGET:/src/test/support/wasm/echo-guest/target" \
  -v "$VOLUME_SDK_TARGET:/src/tui/wasm/guest/target" \
  $example_mounts \
  -e OURO_FORGE_TEST_RUST="$RUST_VERSION" \
  -e OURO_FORGE_TEST_ARGS="$*" \
  -w /src \
  "$IMAGE" \
  bash -euc '
    echo "==> kernel: $(uname -r)"

    export DEBIAN_FRONTEND=noninteractive
    if ! command -v bwrap >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y -qq bubblewrap build-essential curl git pkg-config libssl-dev >/dev/null
    fi
    echo "==> bwrap: $(bwrap --version)"

    # Not root. erlexec refuses to start as root without being told which user to drop to,
    # and every native tool in this runtime goes through it — so the container runs the
    # build and the suite as an ordinary user, which is also what CI does.
    # A bare uid rather than a passwd entry: noble already has a user at 1000, the name
    # differs between images, and nothing here reads a passwd entry — HOME is passed in.
    builder_uid=1000
    builder_gid=1000
    mkdir -p /home/builder
    chown -R "$builder_uid:$builder_gid" /home/builder /cargo /rustup /src/_build /src/deps \
      /src/priv/wasm /src/priv/native /src/tui/target \
      /src/test/support/wasm/echo-guest/target \
      /src/tui/wasm/guest/target /src/tui/wasm/guest/examples/*/target

    cat > /tmp/forge-linux-inner.sh <<"INNER"
set -eu
export PATH="/cargo/bin:$PATH"
export CARGO_HOME=/cargo
export RUSTUP_HOME=/rustup
export MIX_ENV=test
export OUROBOROS_REQUIRE_WASM=1

if ! command -v cargo >/dev/null 2>&1; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path \
    --default-toolchain "$OURO_FORGE_TEST_RUST" --profile minimal
fi
rustup toolchain install "$OURO_FORGE_TEST_RUST" --profile minimal >/dev/null 2>&1 || true
rustup default "$OURO_FORGE_TEST_RUST" >/dev/null
rustup target add wasm32-wasip2 >/dev/null
echo "==> cargo: $(cargo --version)"

# deps/ is a volume seeded once from the host copy, rather than the host copy itself.
# Both halves of that matter. Seeded, because a checkout .git is a FILE pointing at a
# worktree this container cannot see, so mix deps.get cannot fetch the one git dependency.
# A volume, because deps/ is not pure source: erlexec compiles a C port in-tree, and the
# Mach-O objects a Mac leaves there are what a linker in here refuses.
if [ ! -f /src/deps/.seeded-from-host ]; then
  echo "==> seeding deps/ from the host checkout"
  rm -rf /src/deps/* 2>/dev/null || true
  cp -a /host-deps/. /src/deps/
  find /src/deps -name "*.o" -delete
  rm -rf /src/deps/erlexec/priv
  touch /src/deps/.seeded-from-host
fi
git config --global --add safe.directory "*" || true

# The helper and the guests, built here: a Mac checkout carries a Mach-O helper, and a
# component built by another host toolchain is not something to reuse on faith.
cd /src
make wasm
make wasm-guest
make wasm-examples

# The cache the forge builds --offline against, in the cargo home the tests name.
make wasm-sdk-cache CARGO_HOME=/cargo

mix local.hex --force >/dev/null
mix local.rebar --force >/dev/null
mix deps.get >/dev/null
mix compile

mix test test/wasm/forge_test.exs test/agent_effects_test.exs \
  test/provider/native/sandbox_test.exs $OURO_FORGE_TEST_ARGS
INNER

    chmod 0755 /tmp/forge-linux-inner.sh
    exec setpriv --reuid="$builder_uid" --regid="$builder_gid" --clear-groups \
      env HOME=/home/builder \
        OURO_FORGE_TEST_RUST="$OURO_FORGE_TEST_RUST" \
        OURO_FORGE_TEST_ARGS="$OURO_FORGE_TEST_ARGS" \
        /tmp/forge-linux-inner.sh
  '
