#!/bin/bash
set -euo pipefail
ouro_run=/home/ubuntu/ouro-ledger-storage-20261004-r1
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > final2-validation.exit' EXIT
ouro_toolchain=/home/ubuntu/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export OURO_BUILD_REVISION=63d3ede641b7e8c3fc920053da3ac1d698f6b2d1 OURO_BUILD_DIRTY=true
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export OURO_JAIL_BIN="$ouro_run/target/release/ouro-jail" OURO_FIXTURE_BIN="$ouro_run/target/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
python3 - <<'PY'
from pathlib import Path
import hashlib
root = Path.cwd()
paths = {Path("Cargo.toml"), Path("Cargo.lock"), Path("rust-toolchain.toml"), Path("docs/specs/jail-v1/milestone-1-freeze.toml")}
paths.update(p.relative_to(root) for p in (root / "crates").rglob("*") if p.is_file() and not p.is_symlink())
paths.update(p.relative_to(root) for p in (root / "docs/specs").rglob("*.schema.json") if p.is_file() and not p.is_symlink())
with open("final2-source.sha256", "w") as f:
    for path in sorted(paths):
        f.write(hashlib.sha256((root/path).read_bytes()).hexdigest() + "  " + str(path) + "\n")
PY
cat validation-env.txt > ledger-final2.log
grep '^SigIgn:' /proc/self/status >> ledger-final2.log
set +e
systemd-run --user --scope --quiet --unit=ouro-storage-ledger-20261004-r1-final2 "$ouro_toolchain/cargo" test --release -p ouro-ledger --no-fail-fast -- --test-threads=1 >> ledger-final2.log 2>&1
ouro_test_status=$?
printf '%s\n' "$ouro_test_status" > ledger-final2.exit
sha256sum target/release/ouro-jail target/release/ouro-fixture target/release/ouro-ledger > binaries-final2.sha256
systemd-run --user --scope --quiet --unit=ouro-storage-doctor-20261004-r1-ledger-final2 ./target/release/ouro-jail doctor --json > doctor-ledger-final2.json 2> doctor-ledger-final2.stderr
ouro_doctor_status=$?
printf '%s\n' "$ouro_doctor_status" > doctor-ledger-final2.exit
export CARGO_PROFILE_DEV_DEBUG=0
"$ouro_toolchain/cargo" clippy --workspace --all-targets -- -D warnings > clippy-final2.log 2>&1
ouro_clippy_status=$?
printf '%s\n' "$ouro_clippy_status" > clippy-final2.exit
./target/release/xtask i02-scan > i02-scan-final2.log 2>&1
ouro_scan_status=$?
printf '%s\n' "$ouro_scan_status" > i02-scan-final2.exit
sha256sum --check binaries-final2.sha256 > binaries-ledger-final2-check.txt
ouro_binary_status=$?
sha256sum --check final2-source.sha256 > final2-source-check.txt
ouro_source_status=$?
set -e
if (( ouro_test_status != 0 || ouro_doctor_status != 0 || ouro_clippy_status != 0 || ouro_scan_status != 0 || ouro_binary_status != 0 || ouro_source_status != 0 )); then
    exit 1
fi
