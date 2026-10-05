#!/bin/bash
ouro_run=/home/ubuntu/ouro-ledger-retention-20261005-r1
ouro_toolchain=/home/ubuntu/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin
set -euo pipefail
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > validation.exit' EXIT
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export OURO_BUILD_REVISION=5b0b5531628f8612c43c0873cb3a9261c293b847 OURO_BUILD_DIRTY=true
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export OURO_JAIL_BIN="$ouro_run/target/release/ouro-jail" OURO_FIXTURE_BIN="$ouro_run/target/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
{ uname -srmo; "$RUSTC" --version; printf 'revision=%s\ndirty=true\nconformance=1\n' "$OURO_BUILD_REVISION"; grep '^SigIgn:' "/proc/$$/status"; df -h .; } > validation-env.txt
sha256sum --check validation-source.sha256 > source-precheck.log
"$ouro_toolchain/cargo" build --release --locked -p ouro-jail -p ouro-fixture -p ouro-ledger --bins > build.log 2>&1
"$ouro_toolchain/cargo" clippy --release --locked -p ouro-ledger --all-targets -- -D warnings > clippy.log 2>&1
systemd-run --user --scope --quiet --unit=ouro-retention-ledger-20261005-r1 "$ouro_toolchain/cargo" test --release --locked -p ouro-ledger --no-fail-fast -- --test-threads=1 > ledger-tests.log 2>&1
systemd-run --user --scope --quiet --unit=ouro-retention-doctor-20261005-r1 "$OURO_JAIL_BIN" doctor --json > doctor.json 2> doctor.stderr
sha256sum target/release/ouro-jail target/release/ouro-fixture target/release/ouro-ledger > binaries.sha256
sha256sum --check binaries.sha256 > binaries-check.log
sha256sum --check validation-source.sha256 > source-check.log
