# October 5 ledger segment rotation

The storage slice now rotates whole canonical records into ordered segments
at a 64 MiB append boundary. It preserves global sequences, hash links,
request/effect replay identities and exact concatenated NDJSON bytes. Sealed
segments never change. Legacy single-file manifests migrate without rewriting
records. Version 2 reader checkpoints preserve snapshots across rotation and
writer restart, including partially exported UTF-8 records.

## Recovery checks

Eight new store tests cover these boundaries with a reduced test-only segment
threshold (the production threshold remains 64 MiB):

- Multiple rotations, global hash/sequence continuity, byte-exact export and
  original request receipts after restart.
- Failures after successor creation, after its directory sync, before append,
  during partial append, at event sync, projection, manifest and final directory
  sync. Empty successors resume safely; complete tails recover the original
  receipt; partial tails remain untouched and block further admission.
- Recovery sync failure at each segment refuses startup before promoting
  metadata. Recovery uses the descriptor that was validated.
- Missing middle/final segments, swapped contents, altered bytes, sealed-file
  growth, reordered manifests, missing multi-file manifests, extra successors
  and symlinks refuse mutation while preserving the damaged evidence.
- Cursor retry and continuation across restart and further rotation, including
  partially exported UTF-8 records and a snapshot bound to the earlier head.
- Replacing a later segment inode refuses the old cursor even when the new
  file contains identical bytes and the local chain verifies.
- Migration of version 1 manifests and version 1 reader checkpoints.
- Filtered source queries across segments and immutable effect identity replay.

## Validation results

- `OURO_CONFORMANCE=1 cargo +1.98.1 test --workspace -- --test-threads=1`:
  **1,115 passed, 0 failed, 7 ignored**, zero runtime skip markers. The seven
  ignored entries are existing evidence-generation, Unicode reference,
  subprocess-helper and documentation tests; their names are retained in
  `validation.json` and `macos-workspace-tests.log`.
- The ledger subset is **78 passed, 0 failed, 0 ignored**, including all eight
  new rotation regressions, portable daemon tests, reader CLI tests and storage
  recovery tests.
- Strict workspace Clippy, formatting, both Jail/Ledger schema contracts, the
  managed-policy contract, document links, I02 and the tested freeze check pass.
- Three exact pagination homonyms were added to the existing I02 exception
  table. Its nine regression tests, including negative cases, pass in the
  separate `i02-tests.log` run after the workspace run.

`source.sha256` identifies the delivered ledger sources, fixtures, schemas,
dependency files and I02 rules. `validation.json` records the platform, base
revision and scope. Logs belong to this uncommitted rotation implementation;
they are not hosted CI evidence for a new commit.

## Native host validation

The supplied Linux x86_64 VPS and a second ARM64 Mac validated the working-tree
snapshot at base revision `02411d4941ddb07312eb61bb64c3d88a7f2766be`, with
`OURO_BUILD_DIRTY=true`. `native/source.sha256` binds all **528** source and
contract files copied to both hosts; pre/post checks on Linux, the Mac post-check
and the final local check all agree. The runner scripts and threshold harness
are bound separately by `native/harness.sha256`.

- **Linux: 94 ledger tests passed**, including all **15 real jail launch tests**,
  zero failed, ignored or skipped tests. This includes detached ownership,
  cancellation, lost client replies, owner/writer death, exclusion of contained
  children from the store, honest `none`, bounded capture, rotation and recovery.
- **Second Mac: 78 ledger tests passed**, zero failed, ignored or skipped tests.
- Strict Clippy passes on both hosts. The Linux release build and actual jail
  doctor pass (`ready=true`); all three product binary hashes pass. These runs
  are recorded under `native/linux-*` and `native/mac-*`, with aggregate exits 0.
- An independent Python socket client drives the unmodified release daemon past
  its **production 64 MiB threshold**: 130 half-MiB operator notes create two
  segments of 66,654,281 and 1,574,481 bytes. After writer restart, original
  preparation and append receipts replay, a later append remains outside the
  pinned snapshot, and the most recent page retry is identical. The export is
  exactly **68,228,762 bytes** over 1,561 bounded pages with SHA-256
  `9d6ce37dade64c37dfa68dfe757c3afa1cebbae27dd06d06f410c31d998a75d3`.
  The sealed segment remains unchanged and `none` stays `unprotected`.
  `native/linux-threshold-summary.json` records the result. This harness uses
  generated notes; it does not itself launch a jail.

The Pi was reachable, but no pinned Rust toolchain was present. It was not used
for this acceptance; no ARM64 Linux runtime claim follows from these results.

## Validation scope

The local workspace test log uses Rust 1.98.1, `OURO_CONFORMANCE=1` and one
test thread. Linux-only execution tests are not compiled in that local run.
The additional native Linux and Mac runs below test the same source snapshot.
This evidence does not establish managed-worker, provider or native macOS
containment acceptance. Fault injection does not establish physical power-loss
or full-disk behavior.

The separate [freeze refresh](../../../jail-v1/evidence/2026-10-05-freeze/README.md)
records the existing clean Linux conformance result for `db5a9572`. The rotation
changes do not modify Jail build inputs or dependencies.

Retention, pruning, garbage collection and signed custody remain unimplemented.
