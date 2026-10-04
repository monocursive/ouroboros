#!/bin/bash
set -euo pipefail
ouro_run=/Users/monocursive/ouro-ledger-storage-20261004
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > review-validation.exit' EXIT
ouro_toolchain=/Users/monocursive/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export OURO_BUILD_REVISION=63d3ede641b7e8c3fc920053da3ac1d698f6b2d1 OURO_BUILD_DIRTY=true
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3 CARGO_PROFILE_DEV_DEBUG=0
{
    sw_vers
    uname -m
    "$ouro_toolchain/rustc" --version
    printf 'ouro-suite-revision=%s\n' "$OURO_BUILD_REVISION"
    printf 'ouro-suite-dirty=%s\n' "$OURO_BUILD_DIRTY"
} > review-validation-env.txt
shasum -a 256 -c docs/specs/ledger-v1/evidence/2026-10-04-storage/review-source.sha256 > review-source-precheck.txt
cat review-validation-env.txt > review-ledger.log
set +e
"$ouro_toolchain/cargo" test --locked -p ouro-ledger --no-fail-fast >> review-ledger.log 2>&1
ouro_test_status=$?
printf '%s\n' "$ouro_test_status" > review-ledger.exit
shasum -a 256 -c docs/specs/ledger-v1/evidence/2026-10-04-storage/review-source.sha256 > review-source-check.txt
ouro_source_status=$?
set -e
if (( ouro_test_status != 0 || ouro_source_status != 0 )); then
    exit 1
fi
