#!/bin/bash
set -euo pipefail
ouro_run=/home/ubuntu/ouro-ledger-storage-20261004-r1
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > validation.exit' EXIT
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
printf 'ouro-suite-path=%s\nouro-suite-revision=%s\nouro-suite-conformance=%s\nouro-suite-dirty=%s\n' "$PATH" "$OURO_BUILD_REVISION" "$OURO_CONFORMANCE" "$OURO_BUILD_DIRTY" > validation-env.txt
sha256sum Cargo.lock Cargo.toml crates/ouro-ledger/src/projection.rs crates/ouro-ledger/src/store.rs crates/ouro-ledger/src/reader.rs crates/ouro-ledger/src/manifest.rs crates/ouro-ledger/tests/storage_recovery.rs docs/specs/jail-v1/milestone-1-freeze.toml > tested-source.sha256
"$ouro_toolchain/cargo" build --release -p ouro-jail -p ouro-fixture -p ouro-ledger > release-build.log 2>&1
printf '0\n' > release-build.exit
sha256sum target/release/ouro-jail target/release/ouro-fixture target/release/ouro-ledger > binaries.sha256
set +e
systemd-run --user --scope --quiet --unit=ouro-storage-doctor-20261004-r1 ./target/release/ouro-jail doctor --json > doctor.json 2> doctor.stderr
ouro_doctor_status=$?
printf '%s\n' "$ouro_doctor_status" > doctor.exit
set -e
cat validation-env.txt > test.log
set +e
systemd-run --user --scope --quiet --unit=ouro-storage-conformance-20261004-r1 "$ouro_toolchain/cargo" test --workspace --release --no-fail-fast -- --test-threads=1 >> test.log 2>&1
ouro_test_status=$?
printf '%s\n' "$ouro_test_status" > test.exit
set -e
sha256sum --check binaries.sha256 > binaries-check.txt
sha256sum --check tested-source.sha256 > tested-source-check.txt
exit "$ouro_test_status"
