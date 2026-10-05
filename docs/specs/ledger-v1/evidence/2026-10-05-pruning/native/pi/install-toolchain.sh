#!/bin/bash
set -euo pipefail
ouro_run=/home/monocursive/ouro-ledger-pruning-20261005-pi-r1
cd "$ouro_run"
trap 'ouro_status=$?; printf "%s\n" "$ouro_status" > install.exit' EXIT
export CARGO_HOME="$ouro_run/tooling/cargo" RUSTUP_HOME="$ouro_run/tooling/rustup"
mkdir -m 700 tooling
curl --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 -fsSLo tooling/rustup-init https://static.rust-lang.org/rustup/dist/aarch64-unknown-linux-gnu/rustup-init
curl --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 -fsSLo tooling/rustup-init.sha256 https://static.rust-lang.org/rustup/dist/aarch64-unknown-linux-gnu/rustup-init.sha256
(cd tooling && sha256sum --check rustup-init.sha256)
chmod 700 tooling/rustup-init
tooling/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.98.1 --component clippy --component rustfmt
"$CARGO_HOME/bin/rustc" +1.98.1 --version
"$CARGO_HOME/bin/cargo" +1.98.1 --version
