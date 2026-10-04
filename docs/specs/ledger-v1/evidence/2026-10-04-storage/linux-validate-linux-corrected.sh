#!/bin/bash
set -euo pipefail
ouro_run=/home/ubuntu/ouro-ledger-storage-20261004-r1
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > corrected-validation.exit' EXIT
ouro_toolchain=/home/ubuntu/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export OURO_BUILD_REVISION=63d3ede641b7e8c3fc920053da3ac1d698f6b2d1
export OURO_BUILD_DIRTY=true
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
export OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$ouro_run/target/release/ouro-jail"
export OURO_FIXTURE_BIN="$ouro_run/target/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
cat validation-env.txt > test-corrected.log
grep '^SigIgn:' /proc/self/status >> test-corrected.log
sha256sum --check tested-source.sha256 > corrected-source-before.txt
set +e
systemd-run --user --scope --quiet --unit=ouro-storage-conformance-20261004-r1-corrected "$ouro_toolchain/cargo" test --workspace --release --no-fail-fast -- --test-threads=1 >> test-corrected.log 2>&1
ouro_test_status=$?
printf '%s\n' "$ouro_test_status" > corrected-test.exit
systemd-run --user --scope --quiet --unit=ouro-storage-portable-proxy-20261004-r1 "$ouro_toolchain/cargo" test -p ouro-jail --release --test portable_proxy -- --test-threads=1 > portable-proxy-final.log 2>&1
ouro_proxy_status=$?
printf '%s\n' "$ouro_proxy_status" > portable-proxy-final.exit
systemd-run --user --scope --quiet --unit=ouro-storage-doctor-20261004-r1-final ./target/release/ouro-jail doctor --json > doctor-final.json 2> doctor-final.stderr
ouro_doctor_status=$?
printf '%s\n' "$ouro_doctor_status" > doctor-final.exit
export CARGO_PROFILE_DEV_DEBUG=0
"$ouro_toolchain/cargo" clippy --workspace --all-targets -- -D warnings > clippy.log 2>&1
ouro_clippy_status=$?
printf '%s\n' "$ouro_clippy_status" > clippy.exit
"$ouro_toolchain/cargo" build --release -p xtask > xtask-build.log 2>&1
ouro_xtask_status=$?
printf '%s\n' "$ouro_xtask_status" > xtask-build.exit
./target/release/xtask i02-scan > i02-scan.log 2>&1
ouro_scan_status=$?
printf '%s\n' "$ouro_scan_status" > i02-scan.exit
sha256sum --check binaries.sha256 > binaries-final-check.txt
ouro_binary_status=$?
sha256sum --check tested-source.sha256 > tested-source-final-check.txt
ouro_source_status=$?
set -e
if (( ouro_test_status != 0 || ouro_proxy_status != 0 || ouro_doctor_status != 0 || ouro_clippy_status != 0 || ouro_xtask_status != 0 || ouro_scan_status != 0 || ouro_binary_status != 0 || ouro_source_status != 0 )); then
    exit 1
fi
