#!/bin/bash
ouro_run=/Users/monocursive/ouro-ledger-rotation-20261005-r1
ouro_toolchain=/Users/monocursive/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin
set -euo pipefail
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > validation.exit' EXIT
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export OURO_BUILD_REVISION=02411d4941ddb07312eb61bb64c3d88a7f2766be OURO_BUILD_DIRTY=true
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export CARGO_PROFILE_DEV_DEBUG=0
{ sw_vers; uname -m; "$RUSTC" --version; printf 'revision=%s\ndirty=true\nconformance=1\n' "$OURO_BUILD_REVISION"; } > validation-env.txt
shasum -a 256 -c validation-source.sha256 > source-precheck.log
"$ouro_toolchain/cargo" test --locked -p ouro-ledger --no-fail-fast -- --test-threads=1 > ledger-tests.log 2>&1
"$ouro_toolchain/cargo" clippy --locked -p ouro-ledger --all-targets -- -D warnings > clippy.log 2>&1
shasum -a 256 -c validation-source.sha256 > source-check.log
