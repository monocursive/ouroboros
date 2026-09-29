#!/bin/bash
set -eu
cd /Users/monocursive/code/ouroboros
RUN_DIR=$PWD/target/regression-20260929
trap 'echo $? > "$RUN_DIR/macos-exit-code"' EXIT
export OURO_BUILD_REVISION=2c8f28dcda4bc60b2e5ba51b2f8f9d7c93bf5bfa OURO_BUILD_DIRTY=true
export OURO_JAIL_BIN=$PWD/target/debug/ouro-jail OURO_FIXTURE_BIN=$PWD/target/debug/ouro-fixture
date -u +%FT%TZ > "$RUN_DIR/macos-started-at"
cargo +1.98.1 build --locked -p ouro-jail -p ouro-fixture > "$RUN_DIR/macos-build.log" 2>&1
"$OURO_JAIL_BIN" version --json > "$RUN_DIR/macos-build.json"
cargo +1.98.1 test --locked --workspace --no-fail-fast -- --test-threads=1 > "$RUN_DIR/macos-test.log" 2>&1
cargo +1.98.1 clippy --locked --workspace --all-targets -- -D warnings > "$RUN_DIR/macos-clippy.log" 2>&1
date -u +%FT%TZ > "$RUN_DIR/macos-finished-at"
