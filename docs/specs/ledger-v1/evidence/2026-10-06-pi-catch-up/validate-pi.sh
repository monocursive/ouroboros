#!/bin/bash
set -uo pipefail
cd /home/monocursive/ouro-pi-41e6457b
umask 0022
mkdir -p validation
ouro_cache=/home/monocursive/ouro-ledger-pruning-20261005-pi-r1
ouro_toolchain="$ouro_cache/tooling/rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin"
export CARGO_HOME="$ouro_cache/tooling/cargo" RUSTUP_HOME="$ouro_cache/tooling/rustup"
export CARGO_TARGET_DIR="$ouro_cache/target"
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export OURO_BUILD_REVISION=41e6457b009065bd4fe4040b3141da291fb29c9b OURO_BUILD_DIRTY=false
export OURO_JAIL_BIN="$CARGO_TARGET_DIR/release/ouro-jail" OURO_FIXTURE_BIN="$CARGO_TARGET_DIR/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
failed=0
trap 'printf "%s\n" "$failed" > validation/validation.exit' EXIT
run() {
    local label="$1"; shift
    printf '%s\n' "$label" > validation/stage
    "$@" > "validation/$label.log" 2>&1
    local status=$?
    printf '%s\n' "$status" > "validation/$label.exit"
    if [ "$status" -ne 0 ]; then failed=1; fi
    return "$status"
}
{
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -srmo
    tr -d '\0' < /proc/device-tree/model; printf '\n'
    cat /etc/os-release
    "$RUSTC" --version
    bwrap --version
    openssl version
    printf 'revision=%s\ndirty=false\nconformance=1\n' "$OURO_BUILD_REVISION"
    grep '^SigIgn:' "/proc/$$/status"
    grep -E 'CONFIG_(SECURITY_LANDLOCK|UNIX_DIAG|MEMCG)' "/boot/config-$(uname -r)"
    cat /proc/cgroups
    df -h .
} > validation/environment.txt
run source-precheck sha256sum -c source.sha256 || exit 1
run build "$ouro_toolchain/cargo" build --release --locked --workspace --bins || exit 1
run clippy env PATH="$ouro_toolchain:$PATH" "$ouro_toolchain/cargo" clippy --release --locked --workspace --all-targets -- -D warnings || exit 1
run ledger "$ouro_toolchain/cargo" test --release --locked -p ouro-ledger --no-fail-fast -- --test-threads=1
run units "$ouro_toolchain/cargo" test --release --locked -p ouro-jail -p ouro-fixture -p ouro-records --lib --no-fail-fast -- --test-threads=1
run xtask "$ouro_toolchain/cargo" test --release --locked -p xtask -- --test-threads=1
run live "$ouro_toolchain/cargo" test --release --locked -p ouro-jail --test command_rules_linux --test j4_tracer_precision_linux --test j5_arch_refusal_linux --test j5_tracer_foreign_child_linux --test native_capabilities_linux --no-fail-fast -- --test-threads=1
# This kernel lacks UNIX_DIAG. The live capability tests assert agent refusal;
# positive agent conformance belongs to the configured reference VPS.
for profile in tool none; do
    run "matrix-$profile" "$ouro_toolchain/cargo" test --release --locked -p ouro-jail --test j4_closed_set_linux "j4_o01_every_variant_is_one_event_per_result_$profile" -- --exact --test-threads=1
done
run published "$ouro_toolchain/cargo" test --release --locked -p ouro-jail --test j4_closed_set_linux j4_closed_set_the_published_table_is_the_one_this_build_traces -- --exact --test-threads=1
run freeze-tables "$ouro_toolchain/cargo" test --release --locked -p ouro-jail --test portable_freeze -- --test-threads=1
# Landlock refusal runs above. The positive installation test needs a kernel
# with Landlock and is explicitly excluded here, as in the prior Pi lane.
run fixture-identity "$ouro_toolchain/cargo" test --release --locked -p ouro-fixture --test syscall_identity_linux -- --test-threads=1 --skip sandbox_exec_installs_each_layer_before_the_exec
run doctor "$OURO_JAIL_BIN" doctor --json
"$OURO_JAIL_BIN" doctor --profile agent --json > validation/doctor-agent.json 2> validation/doctor-agent.stderr
status=$?
printf '%s\n' "$status" > validation/doctor-agent.exit
if [ "$status" -ne 125 ]; then failed=1; fi
run signing-smoke /bin/bash ./signing-smoke.sh
run source-postcheck sha256sum -c source.sha256
sha256sum "$OURO_JAIL_BIN" "$OURO_FIXTURE_BIN" "$CARGO_TARGET_DIR/release/ouro-ledger" > validation/binaries.sha256
run binaries-check sha256sum -c validation/binaries.sha256
printf 'complete\n' > validation/stage
exit "$failed"
