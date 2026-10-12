#!/bin/sh
set -u
bench_root="$HOME/bench-ouro-startup"
export PATH="$bench_root/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export OURO_CONFORMANCE=1 OURO_BUILD_REVISION=ac1263a0961d5e676c2a03e516848a9fd00dde9b OURO_BUILD_DIRTY=true CARGO_BUILD_JOBS=2
export OURO_FIXTURE_BIN="$bench_root/bin/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus
cd "$bench_root/src"
bench_exe=$(find target/debug/deps -maxdepth 1 -type f -name 'j4_closed_set_linux-*' -perm -111 | head -n 1)
for bench_arm in before after; do
 if [ "$bench_arm" = before ]; then export OURO_JAIL_BIN="$bench_root/bin/ouro-jail-before"; else export OURO_JAIL_BIN="$bench_root/bin/ouro-jail"; fi
 systemd-run --user --scope --quiet -p Delegate=yes "$bench_exe" --test-threads=1 > "$bench_root/results/validation/j4-closed-set-$bench_arm.log" 2>&1
 echo "j4-closed-set-$bench_arm exit=$?"
done
export OURO_JAIL_BIN="$bench_root/bin/ouro-jail"
for bench_test in j4_loss_linux j4_tracer_precision_linux j5_tracer_foreign_child_linux j5_boundary_linux j5_pseudofs_linux observer_j4_linux observer_linux observer_regression_linux review_linux security_alias_linux j5_bwrap_resolution_linux; do
 systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test "$bench_test" -- --test-threads=1 > "$bench_root/results/validation/$bench_test.log" 2>&1
 echo "$bench_test exit=$?"
done
for bench_case in ordinary_file_hints shared_status_and_readonly; do
 systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test linux_mechanisms "$bench_case" -- --test-threads=1 > "$bench_root/results/validation/$bench_case.log" 2>&1
 echo "$bench_case exit=$?"
done
"$bench_root/bin/ouro-jail" doctor --json > "$bench_root/results/validation/doctor-after.json" 2> "$bench_root/results/validation/doctor-after.stderr.log"
echo PI-VALIDATION-ATTEMPTS-COMPLETE
