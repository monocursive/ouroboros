#!/bin/sh
set -eu
bench_source="$1"
bench_host="$2"
bench_root="$HOME/bench-ouro-startup-stable-final"
export PATH="$bench_root/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export OURO_BUILD_REVISION=ac1263a0961d5e676c2a03e516848a9fd00dde9b OURO_BUILD_DIRTY=true CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export OURO_FIXTURE_BIN="$bench_root/bin/ouro-fixture" OURO_JAIL_BIN="$bench_root/bin/ouro-jail"
export XDG_RUNTIME_DIR=/run/user/$(id -u) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus
if [ "$bench_host" = vps ]; then export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0; fi
bench_validation="$bench_root/results/validation"
mkdir -p "$bench_validation"
cd "$bench_source"
cargo +1.98.1 build --locked --release -p ouro-jail -p ouro-fixture > "$bench_validation/build-release.log" 2>&1
cp target/release/ouro-jail "$bench_root/bin/ouro-jail"
cp target/release/ouro-fixture "$bench_root/bin/ouro-fixture"
cargo +1.98.1 clippy --locked -p ouro-jail --all-targets -- -D warnings > "$bench_validation/clippy.log" 2>&1
cargo +1.98.1 test --locked -p ouro-jail --lib -- --test-threads=1 > "$bench_validation/unit-tests.log" 2>&1
if [ "$bench_host" = vps ]; then
 systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test review_linux --test observer_linux --test observer_j4_linux --test observer_regression_linux --test j4_loss_linux --test j4_tracer_precision_linux --test j4_closed_set_linux --test j5_tracer_foreign_child_linux --test j5_boundary_linux --test j5_pseudofs_linux --test security_alias_linux --test j5_bwrap_resolution_linux -- --test-threads=1 > "$bench_validation/security-observer-tests.log" 2>&1
else
 systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test observer_linux --test j5_bwrap_resolution_linux -- --test-threads=1 > "$bench_validation/observer-backend-tests.log" 2>&1
fi
for bench_case in ordinary_file_hints shared_status_and_readonly; do
 systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test linux_mechanisms "$bench_case" -- --test-threads=1 > "$bench_validation/$bench_case.log" 2>&1
done
"$bench_root/bin/ouro-jail" doctor --json > "$bench_validation/doctor-after.json" 2> "$bench_validation/doctor-after.stderr.log"
python3 "$bench_root/harness/finalize_linux_validation.py" "$bench_root" "$bench_source"
sh "$bench_root/harness/profile_and_native.sh" "$bench_source"
echo FINAL-NATIVE-COMPLETE
sh "$bench_root/harness/finish_native_export.sh"
