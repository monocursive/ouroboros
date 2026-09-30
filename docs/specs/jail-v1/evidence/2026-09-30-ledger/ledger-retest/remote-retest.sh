#!/bin/bash
set -euo pipefail
ouro_run=/home/ouro-ci/ouro-ci/ledger-retest-d1a368587e1c
ouro_target=/home/ouro-ci/ouro-ci/runs/20260930T085216Z-a9f8129acb71/target
ouro_products=/home/ouro-ci/ouro-ci/runs/20260930T085216Z-a9f8129acb71/retained-products-a9f8129a
cd "$ouro_run/source"
find crates/ouro-ledger -type f -print0 | sort -z | xargs -0 sha256sum > "$ouro_run/ledger-source.sha256"
ouro_cargo=$(/home/ouro-ci/.cargo/bin/rustup which cargo)
ouro_rustc=$(/home/ouro-ci/.cargo/bin/rustup which rustc)
ouro_rustdoc=$(/home/ouro-ci/.cargo/bin/rustup which rustdoc)
export CARGO_TARGET_DIR="$ouro_target"
export OURO_BUILD_REVISION=d1a368587e1ca53450153035dba3c9a61ed50946
export OURO_BUILD_DIRTY=false
export OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$ouro_products/ouro-jail"
export OURO_FIXTURE_BIN="$ouro_products/ouro-fixture"
export RUSTC="$ouro_rustc" RUSTDOC="$ouro_rustdoc"
"$ouro_cargo" clean --release -p ouro-ledger
"$ouro_cargo" build --release -p ouro-ledger -j2
printf 'ouro-ledger-retest-revision=%s\n' "$OURO_BUILD_REVISION"
printf 'ouro-ledger-retest-conformance=%s\n' "$OURO_CONFORMANCE"
printf 'ouro-ledger-retest-jail=%s\n' "$OURO_JAIL_BIN"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout 180s "$ouro_cargo" test --release -p ouro-ledger --no-fail-fast -j2 -- --test-threads=1
sha256sum "$ouro_target/release/ouro-ledger" > "$ouro_run/ledger-binary.sha256"
(cd "$ouro_products" && sha256sum --check products.sha256) > "$ouro_run/frozen-products-check.txt"
