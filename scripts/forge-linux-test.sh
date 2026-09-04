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
# On Ubuntu 24.04 that is not enough: AppArmor still denies unprivileged writes to
# `/proc/self/setgroups` unless `kernel.apparmor_restrict_unprivileged_userns=0`.
# The script writes that sysctl when it can; the hosted job also sets it on the host.
#
# Since W17 it runs under the *preferred* Linux backend rather than the fallback. `make
# sandbox` builds `ouro-sandbox` here, so `Sandbox.detect/0` finds a helper whose `doctor`
# reports `usable` and `features.read_allow_set`, selects it ahead of bubblewrap, and the
# forge's escape tests are then a proof about Landlock rather than about mount namespaces.
# A run where that helper were missing would silently prove the bubblewrap half twice.
#
# What the container has to build before it can test: the helper (`make wasm`), the sandbox
# helper (`make sandbox`), and the acceptance guest and examples (`make wasm-guest`,
# `make wasm-examples`), because the ones in a Mac checkout are Mach-O and a
# `wasm32-wasip2` component built for a different host toolchain is not something to reuse
# on faith. Then a warmed cargo cache, because the forge builds `--offline` (D19).
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
VOLUME_SANDBOX_HELPER=ouro-forge-sandbox-helper
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
  "$VOLUME_HELPER" "$VOLUME_SANDBOX_HELPER" "$VOLUME_PRIV_NATIVE" "$VOLUME_TUI_TARGET" \
  "$VOLUME_GUEST_TARGET" "$VOLUME_SDK_TARGET"; do
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
  -v "$VOLUME_SANDBOX_HELPER:/src/priv/sandbox" \
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
      # libsctp1: OTP 29 prints a missing-sctp warning on stdout. erlexecs Makefile
      # captures erl -eval into TARGET, and a timestamp with colons is multiple
      # target patterns at the all: rule.
      apt-get install -y -qq bubblewrap build-essential curl git pkg-config libssl-dev libsctp1 >/dev/null
    fi
    echo "==> bwrap: $(bwrap --version)"

    # Ubuntu 24.04 (the hosted runner) runs unprivileged user namespaces under an
    # AppArmor profile that denies /proc/self/setgroups. bwrap and ouro-sandbox both
    # write that file to enter a user namespace. --privileged does not change a host
    # sysctl. The Elixir job already writes 0 on this kernel; do it here too so the
    # script works when run by hand on the same kind of host.
    if [ -w /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
      echo 0 > /proc/sys/kernel/apparmor_restrict_unprivileged_userns
      echo "==> apparmor unprivileged userns: allowed"
    fi

    # Not root. erlexec refuses to start as root without being told which user to drop to,
    # and every native tool in this runtime goes through it — so the container runs the
    # build and the suite as an ordinary user, which is also what CI does.
    # A bare uid rather than a passwd entry: noble already has a user at 1000, the name
    # differs between images, and nothing here reads a passwd entry — HOME is passed in.
    #
    # uid 1000 is that image user, and is the right drop on Docker Desktop (the bind mount
    # is writable as 1000). On a Linux host the checkout is owned by the host user — GitHub
    # Actions is 1001 — and `make wasm-guest` copies echo.wasm onto that bind mount. Follow
    # /src so the copy, and mix compile writing priv/static, are allowed. A Desktop mount
    # that looks like root still wants 1000: erlexec will not start as uid 0.
    src_uid=$(stat -c %u /src)
    src_gid=$(stat -c %g /src)
    if [ "$src_uid" = 0 ]; then
      builder_uid=1000
      builder_gid=1000
    else
      builder_uid=$src_uid
      builder_gid=$src_gid
    fi
    mkdir -p /home/builder
    chown -R "$builder_uid:$builder_gid" /home/builder /cargo /rustup /src/_build /src/deps \
      /src/priv/wasm /src/priv/sandbox /src/priv/native /src/tui/target \
      /src/test/support/wasm/echo-guest/target \
      /src/tui/wasm/guest/target /src/tui/wasm/guest/examples/*/target

    cat > /tmp/forge-linux-inner.sh <<"INNER"
set -eu
export PATH="/cargo/bin:$PATH"
export CARGO_HOME=/cargo
export RUSTUP_HOME=/rustup
export MIX_ENV=test
export OUROBOROS_REQUIRE_WASM=1

echo "==> userns probe (this uid must be able to enter one; bwrap and ouro-sandbox both do)"
if ! bwrap --ro-bind / / --dev /dev --proc /proc -- /bin/true; then
  echo "forge-linux-test: bwrap could not apply a read-only mount as uid $(id -u)." >&2
  echo "  ouro-sandbox fails the same way: open /proc/self/setgroups: Permission denied." >&2
  echo "  Cause: Ubuntu 24.04 kernel.apparmor_restrict_unprivileged_userns. The outer" >&2
  echo "  script writes 0 when that sysctl is writable. On GitHub Actions the workflow" >&2
  echo "  also sets it on the host before docker runs." >&2
  exit 1
fi

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
  find /src/deps -name "*.d" -delete
  rm -rf /src/deps/erlexec/priv
  touch /src/deps/.seeded-from-host
fi
git config --global --add safe.directory "*" || true

# The helper and the guests, built here: a Mac checkout carries a Mach-O helper, and a
# component built by another host toolchain is not something to reuse on faith.
cd /src

# `_build` is a volume that outlives one run, and `mix` links `.../lib/ouroboros/priv` at
# the priv directory of the checkout. The install loop in `make wasm` / `make sandbox`
# would then copy a file onto itself, which coreutils refuses — so the second run of this
# script would die inside `make` rather than in a test. `mix compile` remakes the link.
#
# Exactly that one link, by full path. A `find -name priv -type l` over `_build` also takes
# every dependency’s own priv link with it, and erlexec’s is the port binary every native
# tool in this runtime goes through: the suite then fails to start at all, which is how
# this line came to be written twice.
for env in dev test prod; do
  link="/src/_build/$env/lib/ouroboros/priv"
  if [ -L "$link" ]; then rm -f "$link"; fi
done

make wasm
make sandbox
make wasm-guest
make wasm-examples

# The cache the forge builds --offline against, in the cargo home the tests name.
make wasm-sdk-cache CARGO_HOME=/cargo

mix local.hex --force >/dev/null
mix local.rebar --force >/dev/null
mix deps.get >/dev/null
mix compile

# Which backend the suite is about to run under, recorded before it runs: an
# `ouro-sandbox` that reported itself unusable would fall through to bubblewrap silently,
# and this run would then prove the fallback twice over rather than the preferred backend
# once. `mix compile` has remade the priv link by now, so this is the path detection reads.
cat > /tmp/forge-linux-backend.exs <<"EXS"
detection = Ouroboros.Provider.Native.Sandbox.detect()

IO.puts([
  "    backend: ",
  to_string(detection.backend),
  ", read_fence: ",
  inspect(Map.get(detection, :read_fence)),
  ", fences_reads?: ",
  inspect(Ouroboros.Provider.Native.Sandbox.fences_reads?(detection)),
  "\n    executable: ",
  to_string(detection.executable),
  "\n    ",
  detection.notes
])
EXS

echo "==> backend the forge will build under:"
mix run --no-start /tmp/forge-linux-backend.exs

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
