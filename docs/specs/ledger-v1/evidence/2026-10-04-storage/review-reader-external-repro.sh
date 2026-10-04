#!/bin/zsh
set -euo pipefail

task_evidence_root="$(cd "$(dirname "$0")" && pwd)"
task_repo_root="$(git -C "$task_evidence_root" rev-parse --show-toplevel)"
task_repro_root="$(mktemp -d -t ouro-reader-external)"
trap 'rm -rf "$task_repro_root"' EXIT
mkdir "$task_repro_root/src"
cp "$task_evidence_root/review-reader-external-repro.rs" "$task_repro_root/src/main.rs"
python3 - "$task_repo_root" "$task_repro_root" <<'PY_CARGO'
from pathlib import Path
import json
import sys
repo=Path(sys.argv[1])
scratch=Path(sys.argv[2])
scratch.joinpath('Cargo.toml').write_text('[package]\nname = "ouro-reader-review"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[dependencies]\nouro-ledger = {path = '+json.dumps(str(repo/'crates/ouro-ledger'))+'}\nouro-records = {path = '+json.dumps(str(repo/'crates/ouro-records'))+'}\nserde_json = "1.0.151"\nlibc = "0.2.189"\ntempfile = "3.27.0"\n')
PY_CARGO

cd "$task_repo_root"
shasum -a 256 Cargo.lock Cargo.toml crates/ouro-ledger/Cargo.toml crates/ouro-ledger/src/*.rs crates/ouro-records/src/*.rs > "$task_evidence_root/review-reader-current-source.sha256"
shasum -a 256 docs/specs/ledger-v1/evidence/2026-10-04-storage/review-reader-external-repro.rs docs/specs/ledger-v1/evidence/2026-10-04-storage/review-reader-sync-interposer.c docs/specs/ledger-v1/evidence/2026-10-04-storage/review-reader-external-repro.sh > "$task_evidence_root/review-reader-harness.sha256"
cargo +1.98.1 build --offline --manifest-path "$task_repro_root/Cargo.toml" --target-dir "$task_repo_root/target"
clang -dynamiclib "$task_evidence_root/review-reader-sync-interposer.c" -o "$task_repro_root/libfail_reader_fsync.dylib"
export OURO_READER_RECEIPT_FIXTURE="$task_repo_root/docs/specs/jail-v1/examples/receipt-prepared.json"
{
  print "External reader recovery validation, $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  uname -srm
  cargo +1.98.1 --version
  print "Directory sync fault, then fault removal:"
  DYLD_INSERT_LIBRARIES="$task_repro_root/libfail_reader_fsync.dylib" OURO_READER_FSYNC_MARKER="$task_repro_root/fsync-marker" "$task_repo_root/target/debug/ouro-reader-review"
  print "Reader-directory creation parent sync fault, then fault removal:"
  DYLD_INSERT_LIBRARIES="$task_repro_root/libfail_reader_fsync.dylib" OURO_READER_FSYNC_MARKER="$task_repro_root/fsync-marker" OURO_READER_SYNC_SCOPE=parent OURO_READER_MODE=parent_sync "$task_repo_root/target/debug/ouro-reader-review"
  print "Safe checkpoint corruption:"
  OURO_READER_MODE=corrupt "$task_repo_root/target/debug/ouro-reader-review"
  print "Same-user label forgery with recomputed checksum:"
  for task_repro_mode in labels state coverage empty; do
    OURO_READER_MODE="$task_repro_mode" "$task_repo_root/target/debug/ouro-reader-review"
  done
  print "Caveat: label forgery requires private same-user checkpoint write access; no external custody or managed authorization claim."
  print "Current library source hashes:"
  shasum -a 256 -c "$task_evidence_root/review-reader-current-source.sha256"
} > "$task_evidence_root/review-reader-after.log" 2>&1
cat "$task_evidence_root/review-reader-after.log"
