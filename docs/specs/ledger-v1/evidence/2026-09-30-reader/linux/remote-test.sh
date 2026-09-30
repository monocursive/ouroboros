#!/bin/bash
set -euo pipefail
ouro_revision=$1
[[ "$ouro_revision" =~ ^[0-9a-f]{40}$ ]] || exit 2
ouro_run=/home/ouro-ci/ouro-ci/query-export-20260930
ouro_frozen=/home/ouro-ci/ouro-ci/runs/20260930T085216Z-a9f8129acb71/retained-products-a9f8129a
cd "$ouro_run/source"
find crates/ouro-ledger -type f -print0 | sort -z | xargs -0 sha256sum > "$ouro_run/ledger-source.sha256"
(cd "$ouro_frozen" && sha256sum --check products.sha256) > "$ouro_run/frozen-products-before.txt"
ouro_cargo=$(/home/ouro-ci/.cargo/bin/rustup which cargo)
ouro_rustc=$(/home/ouro-ci/.cargo/bin/rustup which rustc)
ouro_rustdoc=$(/home/ouro-ci/.cargo/bin/rustup which rustdoc)
export CARGO_TARGET_DIR="$ouro_run/target"
export OURO_BUILD_REVISION="$ouro_revision" OURO_BUILD_DIRTY=false
export OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$ouro_frozen/ouro-jail" OURO_FIXTURE_BIN="$ouro_frozen/ouro-fixture"
export RUSTC="$ouro_rustc" RUSTDOC="$ouro_rustdoc"
"$ouro_cargo" clean --release -p ouro-ledger
"$ouro_cargo" build --release -p ouro-ledger -j2
"$ouro_cargo" test --release -p ouro-ledger --no-run -j2
(cd "$ouro_run" && sha256sum target/release/ouro-ledger > ledger-binary.sha256)
printf 'ouro-ledger-retest-revision=%s\n' "$OURO_BUILD_REVISION"
printf 'ouro-ledger-retest-conformance=%s\n' "$OURO_CONFORMANCE"
printf 'ouro-ledger-retest-jail=%s\n' "$OURO_JAIL_BIN"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout 300s "$ouro_cargo" test --release -p ouro-ledger --no-fail-fast -j2 -- --test-threads=1
(cd "$ouro_run" && sha256sum --check ledger-binary.sha256) > "$ouro_run/ledger-binary-check.txt"
(cd "$ouro_frozen" && sha256sum --check products.sha256) > "$ouro_run/frozen-products-after.txt"
