# October 5 ledger retention planning

This slice adds canonical operator `hold` and `release` records and a bounded
`gc --dry-run` preview. It does not delete canonical records, captures or replay
identities. Persistent retention configuration and crash-safe pruning with
retained replay identities and chain anchors remain unimplemented.

## Behavior checked

- Holds survive writer restart and segment rotation. Replaying an old hold after
  a release, or an old release after a new hold, returns its original receipt
  without changing the current hold. Conflicting request identities refuse.
- Both mutations exercise eight persistence/rotation failure points each:
  before write, successor creation, successor sync, partial write, event sync,
  projection, manifest and directory sync. Uncertain writes refuse replay until
  recovery; complete records recover one receipt; partial history stays intact.
- Retention planning keeps active runs, unknown outcomes, held runs, recent
  activity and damaged layouts. It checks the retention boundary, clock rollback,
  bounded pagination and invalid range/path inputs. Known refusal outcomes use
  the jail's `refused` label.
- Durable reader checkpoints pin their run across writer restart, including
  completed pages within their retry lifetime. Expired files remain untouched;
  recent corrupt checkpoints and unsafe paths block candidates conservatively.
- Actual CLI/daemon subprocesses exercise hold/release/retry/restart and JSON
  previews. A dry run does not start a missing writer, append canonical bytes,
  rewrite projections or create reader directories. The CLI and wire protocol
  both reject deletion mode.
- Schema checks reject forged hold provenance/payloads, invalid hold lists,
  oversized plans and contradictory candidate/deletion claims.

## Local validation

`OURO_CONFORMANCE=1 cargo +1.98.1 test -p ouro-ledger -- --test-threads=1`
passes **84 tests, 0 failed, 0 ignored**, with no runtime skip markers. This
includes six new test functions; the persistence test covers 16 fault cases.
The actual logs are in `macos-ledger-tests.log`. Strict ledger Clippy, ledger
schemas, I02, formatting, document links and the tested Jail freeze gate pass.
No Jail build input or dependency was changed.

`source.sha256` binds 531 source/contract files at base revision
`5b0b5531628f8612c43c0873cb3a9261c293b847` with working-tree changes.
These are local development results, not hosted CI evidence for a new commit.

## Native Linux validation

The supplied x86_64 VPS ran the same 531-file snapshot with Rust 1.98.1,
`OURO_CONFORMANCE=1`, release optimization and one test thread. All **100 ledger
tests passed, 0 failed, 0 ignored**, with no runtime skip markers, including
all **15 real jail launch tests**. The release build, strict Clippy and real
jail doctor (`ready=true`) pass. Source hashes before and after the run agree;
all three product binary hashes pass. The aggregate validation exit is zero.

The logs and doctor result are under `native/linux/`. `validate-linux.sh`
records the runner; `runner.sha256` binds it. `validation.json` gives the counts
and scope. The run used an isolated temporary checkout; its build output was
removed after evidence retrieval. No user ledger data was pruned.

## Scope

The preview uses accepted writer state and current metadata/layout; a candidate
still requires full canonical verification before any future deletion. It does
not rescan every record or count capture bytes. Holds and preview do not establish
managed-worker, provider, native macOS containment, physical power-loss or
external custody acceptance. The `none` protection label remains unprotected.
