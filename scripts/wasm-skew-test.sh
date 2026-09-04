#!/bin/sh
# Lane W's precompiled-artifact skew, proved with two real toolchains (docs/WASM.md D22, D24,
# slice W20).
#
# W8 shipped the comparison and tested it with **crafted** headers: a `.cwasm` this build wrote,
# its JSON header rewritten to name another wasmtime or another triple. That is an honest test of
# the comparison — what a node reads *is* the header — and it is not a test that two toolchains
# actually disagree, because one toolchain wrote both sides. §12 said so. This script removes
# that sentence by building the other side for real:
#
#   triple    `ouro-wasm` built inside a Linux container at the same wasmtime, `precompile`d
#             there, carried back, and offered to this machine's own helper.
#   version   `tui/wasm` copied into a scratch workspace with `wasmtime` pinned one patch back,
#             built with the pinned toolchain, `precompile`d, and offered to the same helper.
#
# Both must be refused `precompiled_mismatch`, by name, naming both sides — and the source form
# of the same component must still load, because the whole point of that refusal is that it is a
# fallback and not a dead capability.
#
# Usage: scripts/wasm-skew-test.sh [triple|version|all]   (default: all)
#
# Output lands in `_build/wasm-skew/`, which `test/wasm/skew_test.exs` reads: a real artifact is
# a built binary and this repository does not check those in (see `.gitignore`'s note on
# `test/support/wasm/echo.wasm`), so the Elixir half builds or skips with this script's name in
# the reason. `OURO_WASM_SKEW_DIR=` moves it.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="${OURO_WASM_SKEW_DIR:-$root/_build/wasm-skew}"
what="${1:-all}"

IMAGE="${OURO_SKEW_TEST_IMAGE:-hexpm/elixir:1.20.2-erlang-29.0.5-ubuntu-noble-20260730.1}"
RUST_VERSION="${OURO_SKEW_TEST_RUST:-1.95}"
# The version the copied crate is pinned to. One patch back from the workspace's own resolution:
# the *nearest* other wasmtime that builds under the same MSRV and the same `wasmparser` pin, so
# what differs between the two helpers is a version string and nothing structural.
SKEW_WASMTIME="${OURO_SKEW_WASMTIME:-48.0.0}"

# The same volumes `scripts/forge-linux-test.sh` keeps, and for the same reasons: the toolchain
# and the registry are expensive to rebuild, and the container's ELF `tui/target` must never
# land on top of this Mac's Mach-O one. Reused rather than duplicated so a machine that has run
# the forge suite once already has a warm wasmtime here.
VOLUME_CARGO=ouro-forge-cargo
VOLUME_RUSTUP=ouro-forge-rustup
VOLUME_TUI_TARGET=ouro-forge-tui-target

helper="$root/priv/wasm/ouro-wasm"
guest="$root/test/support/wasm/echo.wasm"

if [ ! -x "$helper" ]; then
  echo "wasm-skew-test: no helper at $helper; run \`make wasm\`." >&2
  exit 1
fi
if [ ! -f "$guest" ]; then
  echo "wasm-skew-test: no acceptance guest at $guest; run \`make wasm-guest\`." >&2
  exit 1
fi

mkdir -p "$out"

this_wasmtime=$("$helper" doctor | sed -n 's/.*"wasmtime": "\([^"]*\)".*/\1/p')
this_target=$("$helper" doctor | sed -n 's/.*"target": "\([^"]*\)".*/\1/p')
guest_sha=$(shasum -a 256 "$guest" | cut -d' ' -f1)

echo "==> this helper: wasmtime $this_wasmtime for $this_target"
echo "==> echo guest:  $guest_sha"

# One `load` of a precompiled artifact, through the real helper's real wire, and the refusal it
# answered. Every field is what a node would send: the artifact's own digest, the *source*
# component's digest out of the manifest, and the path.
offer() {
  artifact="$1"
  artifact_sha=$(shasum -a 256 "$artifact" | cut -d' ' -f1)

  printf '{"jsonrpc":"2.0","id":1,"method":"load","params":{"precompiled":true,"sha256":"%s","component":"%s","path":"%s","kind":"capability"}}\n' \
    "$artifact_sha" "$guest_sha" "$artifact" | "$helper" serve
}

# The source form of the same component, on the same helper. A refusal that left the node unable
# to run the capability at all would not be the fallback D22 promises.
offer_source() {
  printf '{"jsonrpc":"2.0","id":1,"method":"load","params":{"sha256":"%s","path":"%s","kind":"capability"}}\n' \
    "$guest_sha" "$guest" | "$helper" serve
}

# What the header of a produced artifact claims, read without mapping a byte of it.
claims() {
  "$helper" doctor >/dev/null # the helper is usable; `inspect` below is the real read
  printf '{"jsonrpc":"2.0","id":1,"method":"inspect","params":{"path":"%s"}}\n' "$1" | "$helper" serve
}

check_refusal() {
  label="$1"
  answer="$2"
  shift 2

  echo "$answer"

  case "$answer" in
    *precompiled_mismatch*) ;;
    *)
      echo "wasm-skew-test: $label was not refused precompiled_mismatch." >&2
      exit 1
      ;;
  esac

  for needle in "$@"; do
    case "$answer" in
      *"$needle"*) ;;
      *)
        echo "wasm-skew-test: $label's refusal does not name \`$needle\`." >&2
        exit 1
        ;;
    esac
  done
}

## ------------------------------------------------------------------ triple skew

triple_skew() {
  echo
  echo "=== triple skew: an artifact built on Linux, offered to this Mac's helper ==="

  if ! command -v docker >/dev/null 2>&1; then
    echo "wasm-skew-test: docker is not on PATH; the other triple has to come from" >&2
    echo "  somewhere. On a Linux host, build ouro-wasm there and offer the .cwasm to a Mac." >&2
    exit 1
  fi

  for volume in "$VOLUME_CARGO" "$VOLUME_RUSTUP" "$VOLUME_TUI_TARGET"; do
    docker volume create "$volume" >/dev/null
  done

  docker run --rm \
    -v "$root:/src" \
    -v "$out:/out" \
    -v "$VOLUME_CARGO:/cargo" \
    -v "$VOLUME_RUSTUP:/rustup" \
    -v "$VOLUME_TUI_TARGET:/src/tui/target" \
    -e OURO_SKEW_TEST_RUST="$RUST_VERSION" \
    -w /src \
    "$IMAGE" \
    bash -euc '
      echo "==> kernel: $(uname -r)"
      export DEBIAN_FRONTEND=noninteractive
      if ! command -v cc >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq build-essential curl >/dev/null
      fi

      export PATH="/cargo/bin:$PATH"
      export CARGO_HOME=/cargo
      export RUSTUP_HOME=/rustup

      if ! command -v cargo >/dev/null 2>&1; then
        curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path \
          --default-toolchain "$OURO_SKEW_TEST_RUST" --profile minimal
      fi
      rustup toolchain install "$OURO_SKEW_TEST_RUST" --profile minimal >/dev/null 2>&1 || true
      echo "==> cargo: $(cargo +$OURO_SKEW_TEST_RUST --version)"

      cd /src/tui
      cargo +"$OURO_SKEW_TEST_RUST" build --release -p ouro-wasm -j 6

      /src/tui/target/release/ouro-wasm doctor > /out/linux-doctor.json
      grep -E "\"(wasmtime|target)\":" /out/linux-doctor.json

      /src/tui/target/release/ouro-wasm precompile \
        /src/test/support/wasm/echo.wasm /out/echo.triple-skew.cwasm --kind capability
    '

  linux_wasmtime=$(sed -n 's/.*"wasmtime": "\([^"]*\)".*/\1/p' "$out/linux-doctor.json")
  linux_target=$(sed -n 's/.*"target": "\([^"]*\)".*/\1/p' "$out/linux-doctor.json")

  if [ "$linux_target" = "$this_target" ]; then
    echo
    echo "==> triple skew: this helper's target is already $this_target, which is what the"
    echo "    Linux container produces. Two distinct target strings need a Mac (or any host"
    echo "    whose rustc triple is not the container's). No triple-skew.json written; the"
    echo "    Elixir suite skips that record by name."
    return 0
  fi

  echo
  echo "--- what the Linux artifact claims (header only, nothing mapped) ---"
  claims "$out/echo.triple-skew.cwasm"

  echo
  echo "--- offered to this helper (wasmtime $this_wasmtime for $this_target) ---"
  check_refusal "the Linux artifact" "$(offer "$out/echo.triple-skew.cwasm")" \
    "$linux_target" "$this_target"

  echo
  echo "--- and the source form of the same component still loads here ---"
  source_answer=$(offer_source)
  echo "$source_answer"
  case "$source_answer" in
    *'"precompiled":false'*) ;;
    *)
      echo "wasm-skew-test: the source form did not load; the refusal is not a fallback." >&2
      exit 1
      ;;
  esac

  cat > "$out/triple-skew.json" <<JSON
{
  "kind": "triple",
  "artifact": "echo.triple-skew.cwasm",
  "component_sha256": "$guest_sha",
  "produced_by": { "wasmtime": "$linux_wasmtime", "target": "$linux_target" },
  "read_by": { "wasmtime": "$this_wasmtime", "target": "$this_target" }
}
JSON
  echo
  echo "==> triple skew: refused by name, both triples in the message."
}

## ----------------------------------------------------------------- version skew

version_skew() {
  echo
  echo "=== version skew: an artifact built by wasmtime $SKEW_WASMTIME, on this machine ==="

  work="$out/version-skew"
  rm -rf "$work"
  mkdir -p "$work"

  # A workspace of exactly the shape `tui/` has, because `tui/wasm/build.rs` reads the resolved
  # wasmtime out of `../Cargo.lock` — the lock is where the version string in the header comes
  # from, and a copy without a workspace root above it would report `unknown` and prove nothing.
  cp -R "$root/tui/wasm" "$work/wasm"
  rm -rf "$work/wasm/target" "$work/wasm/guest/target"
  cat > "$work/Cargo.toml" <<'TOML'
[workspace]
members = ["wasm"]
resolver = "2"
TOML

  # The pin, and nothing else about the crate. `wasmparser` stays where `tui/wasm/Cargo.toml`
  # pinned it: a checker walking different bytes from the compiler it protects is exactly what
  # that `=` exists to prevent, and relaxing it here would make this a test of two crates.
  sed -e "s/^wasmtime = { version = \"48\"/wasmtime = { version = \"=$SKEW_WASMTIME\"/" \
    "$work/wasm/Cargo.toml" > "$work/pinned.toml"
  mv "$work/pinned.toml" "$work/wasm/Cargo.toml"

  if ! grep -q "^wasmtime = { version = \"=$SKEW_WASMTIME\"" "$work/wasm/Cargo.toml"; then
    echo "wasm-skew-test: the wasmtime line in tui/wasm/Cargo.toml is not the shape this pin edits." >&2
    exit 1
  fi
  grep -n '^wasmtime = ' "$work/wasm/Cargo.toml"

  (cd "$work" && cargo "+$RUST_VERSION" build --release -j 6)

  "$work/target/release/ouro-wasm" doctor > "$out/skewed-doctor.json"
  skewed_wasmtime=$(sed -n 's/.*"wasmtime": "\([^"]*\)".*/\1/p' "$out/skewed-doctor.json")
  skewed_target=$(sed -n 's/.*"target": "\([^"]*\)".*/\1/p' "$out/skewed-doctor.json")
  echo "==> skewed helper: wasmtime $skewed_wasmtime for $skewed_target"

  if [ "$skewed_wasmtime" = "$this_wasmtime" ]; then
    echo "wasm-skew-test: the pinned build reports the same wasmtime as this one; the pin did not take." >&2
    exit 1
  fi

  "$work/target/release/ouro-wasm" precompile \
    "$guest" "$out/echo.version-skew.cwasm" --kind capability

  echo
  echo "--- what the skewed artifact claims (header only) ---"
  claims "$out/echo.version-skew.cwasm"

  echo
  echo "--- offered to this helper (wasmtime $this_wasmtime for $this_target) ---"
  check_refusal "the wasmtime-$skewed_wasmtime artifact" \
    "$(offer "$out/echo.version-skew.cwasm")" "$skewed_wasmtime" "$this_wasmtime"

  cat > "$out/version-skew.json" <<JSON
{
  "kind": "version",
  "artifact": "echo.version-skew.cwasm",
  "component_sha256": "$guest_sha",
  "produced_by": { "wasmtime": "$skewed_wasmtime", "target": "$skewed_target" },
  "read_by": { "wasmtime": "$this_wasmtime", "target": "$this_target" }
}
JSON
  echo
  echo "==> version skew: refused by name, both versions in the message."
}

case "$what" in
  triple) triple_skew ;;
  version) version_skew ;;
  all)
    triple_skew
    version_skew
    ;;
  *)
    echo "wasm-skew-test: unknown argument \`$what\`; it is triple, version or all." >&2
    exit 2
    ;;
esac

echo
echo "==> artifacts and their records are in $out"
ls -l "$out"
