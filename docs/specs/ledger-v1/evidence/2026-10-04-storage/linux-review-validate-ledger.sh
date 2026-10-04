#!/bin/bash
set -euo pipefail
ouro_run=/home/ubuntu/ouro-ledger-storage-20261004-r1
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > review-validation.exit' EXIT
ouro_toolchain=/home/ubuntu/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export OURO_BUILD_REVISION=63d3ede641b7e8c3fc920053da3ac1d698f6b2d1 OURO_BUILD_DIRTY=true
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$ouro_run/target/release/ouro-jail" OURO_FIXTURE_BIN="$ouro_run/target/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
{
    printf 'ouro-suite-path=%s\n' "$PATH"
    printf 'ouro-suite-revision=%s\n' "$OURO_BUILD_REVISION"
    printf 'ouro-suite-conformance=%s\n' "$OURO_CONFORMANCE"
    printf 'ouro-suite-dirty=%s\n' "$OURO_BUILD_DIRTY"
    printf 'ouro-suite-toolchain=%s\n' "$ouro_toolchain"
    printf 'ouro-suite-fixture-config=isolated-by-fixture\n'
    grep '^SigIgn:' "/proc/$$/status"
} > review-validation-env.txt
sha256sum --check review-source.sha256 > review-source-precheck.txt
set +e
"$ouro_toolchain/cargo" build --release --locked -p ouro-jail -p ouro-fixture -p ouro-ledger --bins > review-build.log 2>&1
ouro_build_status=$?
printf '%s\n' "$ouro_build_status" > review-build.exit
set -e
if (( ouro_build_status != 0 )); then
    exit "$ouro_build_status"
fi
cat review-validation-env.txt > review-ledger.log
set +e
systemd-run --user --scope --quiet --unit=ouro-storage-ledger-20261004-r1-review "$ouro_toolchain/cargo" test --release --locked -p ouro-ledger --no-fail-fast -- --test-threads=1 >> review-ledger.log 2>&1
ouro_test_status=$?
printf '%s\n' "$ouro_test_status" > review-ledger.exit
sha256sum target/release/ouro-jail target/release/ouro-fixture target/release/ouro-ledger > review-binaries.sha256
systemd-run --user --scope --quiet --unit=ouro-storage-doctor-20261004-r1-review ./target/release/ouro-jail doctor --json > review-doctor.json 2> review-doctor.stderr
ouro_doctor_status=$?
printf '%s\n' "$ouro_doctor_status" > review-doctor.exit
sha256sum --check review-binaries.sha256 > review-binaries-check.txt
ouro_binary_status=$?
sha256sum --check review-source.sha256 > review-source-check.txt
ouro_source_status=$?
set -e
if (( ouro_test_status != 0 || ouro_doctor_status != 0 || ouro_binary_status != 0 || ouro_source_status != 0 )); then
    exit 1
fi
