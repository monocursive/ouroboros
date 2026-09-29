#!/bin/bash
set -eu
cd /home/ubuntu/ouroboros
RUN_DIR=$PWD/target/regression-20260929
trap 'echo $? > "$RUN_DIR/exit-code"' EXIT
export XDG_RUNTIME_DIR=/run/user/$(id -u)
CARGO_EXE=$(/home/ubuntu/.cargo/bin/rustup which --toolchain 1.98.1 cargo)
export RUSTC=$(/home/ubuntu/.cargo/bin/rustup which --toolchain 1.98.1 rustc)
export RUSTDOC=$(/home/ubuntu/.cargo/bin/rustup which --toolchain 1.98.1 rustdoc)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export OURO_BUILD_REVISION=2c8f28dcda4bc60b2e5ba51b2f8f9d7c93bf5bfa OURO_BUILD_DIRTY=true
export OURO_CONFORMANCE=1
export OURO_JAIL_BIN=$PWD/target/release/ouro-jail OURO_FIXTURE_BIN=$PWD/target/release/ouro-fixture
date -u +%FT%TZ > "$RUN_DIR/started-at"
"$CARGO_EXE" build --locked --release -j2 -p ouro-jail -p ouro-fixture -p xtask > "$RUN_DIR/build.log" 2>&1
"$OURO_JAIL_BIN" version --json > "$RUN_DIR/build.json"
sha256sum "$OURO_JAIL_BIN" "$OURO_FIXTURE_BIN" > "$RUN_DIR/binaries.sha256"
systemd-run --user --scope --quiet --unit=ouro-regression-doctor-20260929 "$OURO_JAIL_BIN" doctor --json > "$RUN_DIR/doctor.json" 2> "$RUN_DIR/doctor.stderr"
export CARGO_EXE
systemd-run --user --scope --quiet --unit=ouro-regression-20260929 timeout --signal=TERM --kill-after=15s 1800s /bin/bash -c '
  echo "ouro-suite-path=$PATH"
  echo "ouro-suite-revision=${OURO_BUILD_REVISION}+dirty"
  echo "ouro-suite-conformance=$OURO_CONFORMANCE"
  exec "$CARGO_EXE" test --locked --workspace --release -j2 --no-fail-fast -- --test-threads=1
' > "$RUN_DIR/test.log" 2>&1
date -u +%FT%TZ > "$RUN_DIR/finished-at"
