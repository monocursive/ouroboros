#!/bin/sh
# The `ouro-sandbox` enforcement proof, runnable from a Mac.
#
# `tui/sandbox`'s unit tests are portable and run under a plain `cargo test` anywhere.
# `tui/sandbox/tests/linux_enforcement.rs` is a different kind of test: it drives the real
# binary against a real workspace and asserts on what the kernel actually did. That needs a
# Linux kernel with Landlock (5.13+), and creating a user namespace at all needs a
# privileged container — Docker's default seccomp profile denies `unshare(CLONE_NEWUSER)`,
# which is why `--privileged` is not optional here and is not a hint that the sandbox needs
# privileges to *work*.
#
# The `fs_filter.c` shared object is compiled first, because the one semantic Landlock
# cannot express — refusing to create a `.git` that did not exist when the command started
# — is still carried by that `LD_PRELOAD` shim. Without it that test skips, loudly, rather
# than passing on nothing.
#
# Usage: scripts/sandbox-linux-test.sh [extra cargo test args]

set -eu

IMAGE="${OURO_SANDBOX_TEST_IMAGE:-rust:1.88}"
VOLUME_CARGO=ouro-sandbox-cargo
VOLUME_TARGET=ouro-sandbox-target

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v docker >/dev/null 2>&1; then
  echo "sandbox-linux-test: docker is not on PATH." >&2
  echo "  The enforcement suite needs a Linux kernel. On a Linux host you can instead run:" >&2
  echo "    cd tui && cargo test -p ouro-sandbox" >&2
  exit 1
fi

docker volume create "$VOLUME_CARGO" >/dev/null
docker volume create "$VOLUME_TARGET" >/dev/null

# --privileged: user namespaces, and nothing else. See the header.
exec docker run --rm --privileged \
  -v "$root:/src" \
  -v "$VOLUME_CARGO:/cargo" \
  -v "$VOLUME_TARGET:/target" \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/target \
  -w /src/tui \
  "$IMAGE" \
  sh -euc '
    echo "==> kernel: $(uname -r)"
    cc -shared -fPIC -ldl -o /tmp/libouro_fs_filter.so /src/c_src/fs_filter.c
    echo "==> fs_filter.c built; the name-based create denial has a layer in this run"
    export OUROBOROS_FS_FILTER_LIBRARY=/tmp/libouro_fs_filter.so
    cargo build -q -p ouro-sandbox
    echo "==> doctor, from the binary this run just built:"
    /target/debug/ouro-sandbox doctor
    cargo test -p ouro-sandbox -- --nocapture '"$*"'
  '
