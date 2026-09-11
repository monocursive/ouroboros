#!/usr/bin/env bash
# Cloud Agent install for Ouroboros. Idempotent: it may run again on a warm checkout or a
# restored snapshot, so every step either converges or is a no-op the second time.
#
# The versions match .github/workflows/ci.yml: Elixir 1.20 / Erlang OTP 29 (installed with
# mise, which ships precompiled OTP builds), Rust 1.95 (wasmtime 48's MSRV, needed by
# `make wasm`/`make release-tarball`). Node 22 is already on the base image and is only used
# by the Playwright browser suite.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ELIXIR_VERSION="1.20.4-otp-29"
ERLANG_VERSION="29.0.6"
RUST_VERSION="1.95"

log() { printf '==> %s\n' "$*"; }

# 1. System packages.
#
#   * gawk: the wasm suites drive scripted `#!/bin/sh` + `awk` stand-in helpers over a pipe
#     that stays open (an Erlang port). Debian/Ubuntu's default `awk` is mawk, which
#     block-buffers stdin and never answers a single line until EOF, so the pool's handshake
#     to those fake helpers times out. GitHub's ubuntu-24.04 runners ship gawk (line
#     buffered), which is why CI is green; we match it and make gawk the default `awk`.
#   * bubblewrap: the runtime spawns the `ouro-wasm` containment helper under bwrap, and
#     refuses to run wasm at all when no sandbox backend can fence reads and network.
#   * the rest are Erlang/OTP build/runtime libraries mise's precompiled build links against.
log "installing system packages (gawk, bubblewrap, Erlang libraries)"
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  gawk bubblewrap \
  build-essential autoconf m4 libncurses-dev libssl-dev libssh-dev unixodbc-dev \
  libgmp-dev libwxgtk3.2-dev libwxgtk-webview3.2-dev libpng-dev libglu1-mesa-dev \
  libsctp-dev curl git unzip

log "making gawk the default awk"
if [ -x /usr/bin/gawk ]; then
  sudo update-alternatives --install /usr/bin/awk awk /usr/bin/gawk 100
  sudo update-alternatives --set awk /usr/bin/gawk
fi

# 2. mise, then Erlang/OTP + Elixir through it.
if ! command -v mise >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/mise" ]; then
  log "installing mise"
  curl -fsSL https://mise.run | sh
fi
export PATH="$HOME/.local/bin:$PATH"

# A login shell for a future agent needs mise's tools on PATH without an explicit activate.
if ! grep -q 'mise activate bash' "$HOME/.bashrc" 2>/dev/null; then
  {
    echo 'export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"'
    echo 'eval "$($HOME/.local/bin/mise activate bash)"'
  } >> "$HOME/.bashrc"
fi

log "installing Erlang/OTP ${ERLANG_VERSION} and Elixir ${ELIXIR_VERSION}"
mise use -g "erlang@${ERLANG_VERSION}" "elixir@${ELIXIR_VERSION}"
eval "$(mise activate bash --shims)"

log "installing Hex and Rebar"
mix local.hex --force
mix local.rebar --force

# 3. Rust 1.95 with the wasm32 target and the components make/CI need.
log "installing Rust ${RUST_VERSION} toolchain + wasm32-wasip2"
rustup toolchain install "${RUST_VERSION}" --profile minimal --component rustfmt,clippy
rustup default "${RUST_VERSION}"
rustup target add wasm32-wasip2

# 4. Elixir dependencies and a full compile (this runs the erlexec patch + web-asset copy).
log "fetching and compiling Elixir dependencies"
mix deps.get
mix compile

# 5. The WebAssembly containment helper, the acceptance guest, and the SDK example
#    components. `make wasm` embeds the helper into priv/wasm; the guest and examples are the
#    real components the lane-W acceptance suites load.
log "building the wasm helper, acceptance guest, and example components"
make wasm
make wasm-guest
make wasm-examples

# 6. Warm the forge's cargo registry cache in this node's own CARGO_HOME. The forge builds
#    `--locked --offline`, so a cold cache is a refusal, not a fetch. CARGO_HOME defaults to
#    ~/.cargo when unset (as on CI); this base image sets it to /usr/local/cargo.
log "warming the forge cargo registry cache in ${CARGO_HOME:-$HOME/.cargo}"
make wasm-sdk-cache CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

# 7. The debug `ouro` client, which boots and supervises the dev runtime (`make dev`,
#    `make web`, `make daemon`) and is the process-incarnation helper the boot gate needs.
log "building the debug ouro client"
( cd tui && cargo build --bin ouro )

log "install complete"
