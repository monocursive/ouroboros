#!/bin/bash
set -uo pipefail
cd "$1"
ouro_toolchain="$2"
ouro_cache="$3"
mkdir -p validation
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_TARGET_DIR="$ouro_cache/target" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
if [ -d "$ouro_cache/tooling/cargo" ]; then
    export CARGO_HOME="$ouro_cache/tooling/cargo" RUSTUP_HOME="$ouro_cache/tooling/rustup"
fi
export OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$CARGO_TARGET_DIR/release/ouro-jail" OURO_FIXTURE_BIN="$CARGO_TARGET_DIR/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
failed=0
trap 'printf "%s\n" "$failed" > validation/validation.exit' EXIT
run() {
    local label="$1"; shift
    printf '%s\n' "$label" > validation/stage
    "$@" > "validation/$label.log" 2>&1
    local status=$?
    printf '%s\n' "$status" > "validation/$label.exit"
    if [ "$status" -ne 0 ]; then failed=1; fi
    return "$status"
}
{
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -srmo
    cat /etc/os-release
    "$RUSTC" --version
    bwrap --version
    printf 'OURO_CONFORMANCE=1\nCARGO_INCREMENTAL=0\n'
} > validation/environment.txt
run source-precheck sha256sum -c source.sha256 || exit 1
run build "$ouro_toolchain/cargo" build --release --locked -p ouro-ledger || exit 1
run clippy env PATH="$ouro_toolchain:$PATH" "$ouro_toolchain/cargo" clippy --release --locked -p ouro-ledger --all-targets -- -D warnings || exit 1
run ledger "$ouro_toolchain/cargo" test --release --locked -p ouro-ledger --no-fail-fast -- --test-threads=1
run doctor "$OURO_JAIL_BIN" doctor --json
run source-postcheck sha256sum -c source.sha256
sha256sum "$OURO_JAIL_BIN" "$OURO_FIXTURE_BIN" "$CARGO_TARGET_DIR/release/ouro-ledger" > validation/binaries.sha256
run binaries-check sha256sum -c validation/binaries.sha256
printf 'complete\n' > validation/stage
exit "$failed"
