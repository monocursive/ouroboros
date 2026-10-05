#!/bin/bash
set -uo pipefail
cd /home/monocursive/ouro-ledger-pruning-20261005-pi-r1
export CARGO_HOME="$PWD/tooling/cargo" RUSTUP_HOME="$PWD/tooling/rustup"
export PATH="$RUSTUP_HOME/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"
export OURO_BUILD_REVISION="2d88db2295eecff139e983cf3206f7e222ac12d9" OURO_BUILD_DIRTY=false CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$PWD/target/release/ouro-jail" OURO_FIXTURE_BIN="$PWD/target/release/ouro-fixture"
failed=0
run() {
    local label="$1"; shift
    "$@" > "arm64-$label-r5.log" 2>&1
    local status=$?
    printf '%s\n' "$status" > "arm64-$label-r5.exit"
    if [ "$status" -ne 0 ]; then failed=1; fi
    return "$status"
}
run source-precheck sha256sum -c arm64-source-r5.sha256 || exit 1
run clippy cargo clippy --release --locked -p ouro-jail -p ouro-fixture -p ouro-ledger --all-targets -- -D warnings || exit 1
run build cargo build --release --locked -p ouro-jail -p ouro-fixture -p ouro-ledger --bins || exit 1
run unit cargo test --release --locked -p ouro-jail --lib -- --test-threads=1
run live cargo test --release --locked -p ouro-jail --test command_rules_linux --test j4_tracer_precision_linux --test j5_arch_refusal_linux --test j5_tracer_foreign_child_linux --test native_capabilities_linux --no-fail-fast -- --test-threads=1
# CONFIG_UNIX_DIAG is absent: agent refusal is exercised above; the positive
# agent matrix runs on the reference VPS. No unsupported kernel feature is skipped silently.
for profile in tool none; do
    run "matrix-$profile" cargo test --release --locked -p ouro-jail --test j4_closed_set_linux "j4_o01_every_variant_is_one_event_per_result_$profile" -- --exact --test-threads=1
done
run published cargo test --release --locked -p ouro-jail --test j4_closed_set_linux j4_closed_set_the_published_table_is_the_one_this_build_traces -- --exact --test-threads=1
run freeze-tables cargo test --release --locked -p ouro-jail --test portable_freeze -- --test-threads=1
run fixture-unit cargo test --release --locked -p ouro-fixture --lib -- --test-threads=1
# CONFIG_SECURITY_LANDLOCK is absent. Its refusal is exercised above; the
# positive Landlock identity test runs on the reference VPS.
run fixture-identity cargo test --release --locked -p ouro-fixture --test syscall_identity_linux -- --test-threads=1 --skip sandbox_exec_installs_each_layer_before_the_exec
run ledger cargo test --release --locked -p ouro-ledger --no-fail-fast -- --test-threads=1
run doctor "$OURO_JAIL_BIN" doctor --json
"$OURO_JAIL_BIN" doctor --profile agent --json > arm64-doctor-agent-r5.json 2> arm64-doctor-agent-r5.stderr
status=$?
printf '%s\n' "$status" > arm64-doctor-agent-r5.exit
if [ "$status" -ne 125 ]; then failed=1; fi
run source-postcheck sha256sum -c arm64-source-r5.sha256
sha256sum target/release/ouro-jail target/release/ouro-fixture target/release/ouro-ledger > arm64-binaries-r5.sha256
printf '%s\n' "$failed" > arm64-validation-r5.exit
exit "$failed"
