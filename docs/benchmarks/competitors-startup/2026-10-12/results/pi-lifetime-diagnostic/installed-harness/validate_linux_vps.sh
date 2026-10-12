#!/bin/sh
set -eu
bench_source="$1"
bench_root="$HOME/bench-ouro-startup"
export PATH="$bench_root/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export OURO_BUILD_REVISION=ac1263a0961d5e676c2a03e516848a9fd00dde9b
export OURO_BUILD_DIRTY=true CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
# Debug symbols do not affect assertions or runtime flags; fit the build quota.
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
bench_validation="$bench_root/results/validation"
mkdir -p "$bench_validation"
cd "$bench_source"
cp target/release/ouro-jail "$bench_root/bin/ouro-jail"
cp target/release/ouro-fixture "$bench_root/bin/ouro-fixture"
cp target/release/ouro-jail "$bench_root/bin/ouro-jail-v3"
cargo +1.98.1 clippy --locked -p ouro-jail --all-targets -- -D warnings > "$bench_validation/clippy.log" 2>&1
cargo +1.98.1 test --locked -p ouro-jail --lib -- --test-threads=1 > "$bench_validation/unit-tests.log" 2>&1
# Every test is serialized. The scope delegates controllers without changing
# host restrictions; it is the same repository-standard validation context.
systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test review_linux --test observer_linux --test observer_j4_linux --test observer_regression_linux --test j4_loss_linux --test j4_tracer_precision_linux --test j4_closed_set_linux --test j5_tracer_foreign_child_linux --test j5_boundary_linux --test j5_pseudofs_linux --test security_alias_linux --test j5_bwrap_resolution_linux -- --test-threads=1 > "$bench_validation/security-observer-tests.log" 2>&1
systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test linux_mechanisms ordinary_file_hints -- --test-threads=1 > "$bench_validation/file-hint-regression.log" 2>&1
systemd-run --user --scope --quiet -p Delegate=yes cargo +1.98.1 test --locked -p ouro-jail --test linux_mechanisms shared_status_and_readonly -- --test-threads=1 > "$bench_validation/shared-probe-regression.log" 2>&1
"$bench_root/bin/ouro-jail" doctor --json > "$bench_validation/doctor-after.json" 2> "$bench_validation/doctor-after.stderr.log"
python3 - "$bench_root" "$bench_source" <<'PY'
from pathlib import Path
import hashlib,json,sys
root,source=map(Path,sys.argv[1:])
names=['crates/ouro-jail/src/platform/linux/fs.rs','crates/ouro-jail/src/platform/linux/platform.rs','crates/ouro-jail/src/platform/linux/probe.rs','crates/ouro-jail/src/platform/linux/tracer/mod.rs','crates/ouro-jail/tests/linux_mechanisms.rs']
(root/'results/validation/source-files.json').write_text(json.dumps({name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in names},indent=2)+'\n')
before=json.loads((root/'results/doctor-before.json').read_text())
after=json.loads((root/'results/validation/doctor-after.json').read_text())
statuses=lambda report:{r['name']:(r['status'],r['reason_code'],r['mechanism']) for r in report['capabilities']}
assert statuses(before)==statuses(after),'Doctor capability declarations changed'
assert after['build']['rustc'].startswith('rustc 1.98.1 ')
assert after['build']['opt_level']=='3' and not after['build']['debug_assertions']
print('Doctor statuses identical; Rust 1.98.1 release build confirmed')
PY
echo LINUX-VALIDATION-COMPLETE
