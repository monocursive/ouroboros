#!/bin/bash
set -uo pipefail
cd /home/monocursive/ouro-ledger-pruning-20261005-pi-r1
export CARGO_HOME="$PWD/tooling/cargo" RUSTUP_HOME="$PWD/tooling/rustup"
export PATH="$RUSTUP_HOME/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"
export OURO_BUILD_REVISION=2d88db2295eecff139e983cf3206f7e222ac12d9 OURO_BUILD_DIRTY=false CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
freeze=docs/specs/jail-v1/milestone-1-freeze.toml
backup=$(mktemp)
cp "$freeze" "$backup"
restore() { cp "$backup" "$freeze"; rm -f "$backup"; }
trap restore EXIT
cp /tmp/ouro-arm64-final-freeze.toml "$freeze"
cargo test --release --locked -p ouro-jail --test portable_freeze -- --test-threads=1 > arm64-final-freeze.log 2>&1
status=$?
printf '%s\n' "$status" > arm64-final-freeze.exit
exit "$status"
