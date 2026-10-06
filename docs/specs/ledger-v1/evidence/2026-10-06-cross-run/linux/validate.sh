#!/bin/bash
set -euo pipefail
cd /home/ubuntu/ouro-cross-run-eb84b9ec
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > validation.exit' EXIT
umask 0022
ouro_toolchain=/home/ubuntu/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export RUSTC="$ouro_toolchain/rustc" RUSTDOC="$ouro_toolchain/rustdoc"
export CARGO_TARGET_DIR=/home/ubuntu/ouro-ledger-storage-20261004-r1/target
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 OURO_CONFORMANCE=1
export OURO_BUILD_REVISION=eb84b9ec3db5a0be8efd9a777835aff64995a8ab OURO_BUILD_DIRTY=false
export OURO_JAIL_BIN="$CARGO_TARGET_DIR/release/ouro-jail" OURO_FIXTURE_BIN="$CARGO_TARGET_DIR/release/ouro-fixture"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
python3 - <<'PY'
from pathlib import Path
import hashlib
paths=[p for root in ['crates','docs/specs'] for p in Path(root).rglob('*') if p.is_file() and 'evidence' not in p.parts]
paths += [Path(p) for p in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
Path('source.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p)+'\n' for p in sorted(paths)))
PY
"$ouro_toolchain/cargo" build --release --locked -p ouro-jail -p ouro-ledger -p ouro-fixture > build.log 2>&1
chmod go-w "$OURO_JAIL_BIN" "$OURO_FIXTURE_BIN" "$CARGO_TARGET_DIR/release/ouro-ledger"
systemd-run --user --scope --quiet --unit=ouro-cross-run-doctor-eb84b9ec "$OURO_JAIL_BIN" doctor --json > doctor.json 2> doctor.stderr
systemd-run --user --scope --quiet --unit=ouro-cross-run-eb84b9ec "$ouro_toolchain/cargo" test --release --locked -p ouro-ledger --no-fail-fast -- --test-threads=1 > ledger-tests.log 2>&1
sha256sum "$OURO_JAIL_BIN" "$OURO_FIXTURE_BIN" "$CARGO_TARGET_DIR/release/ouro-ledger" > binaries.sha256
sha256sum --check source.sha256 > source-check.log
