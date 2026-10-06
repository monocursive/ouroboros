# Unsigned portable evidence bundles, 2026-10-06

Implementation and native source: `76eaafee477b06e10e9fc572740f2a91c919db29`
on `dev`. The evidence commit follows this implementation without changing its
runtime or tests. `source.json` records the clean archive digest. The 405 source
paths and hashes in `local/source.sha256` and `linux/source.sha256` match; their
entry ordering differs because one sorts strings and the other sorts paths.
The native inventory also passed its post-test checksum check.

## Behavior and limits

`bundle RUN --output DIR [--capture stdout] [--capture stderr]` exports exact
canonical records, a receipt array derived from their embedded receipts, and
only explicitly selected captures. `verify-bundle DIR` checks that directory
offline, without opening or starting a node writer. It uses the same canonical
schema, chain, transition and receipt-binding replay as store recovery.

The flat manifest carries the historical canonical projection and member sizes
and hashes. Capture hashes explicitly have the basis `bundle_time`: the current
launch receipts do not attest original capture content hashes. Coverage gaps,
incomplete or truncated capture metadata, pending/terminal state, and
`child_protection` remain independent of successful local verification.
No vendor state is copied. Omitted capture metadata does not promise that the
omitted bytes remain available at the source node.

Creation pins the reader snapshot against history and capture GC, applies
64 MiB / 10,000-record / 20,000-page limits, limits each capture to 16 MiB and
each JSON member to 4 MiB, and checks a 300-second work budget between reads and
before publication. Files are synchronized in a private temporary directory,
verified, and atomically published without replacing any existing destination.
Offline verification rejects unsafe paths, links, extra/missing members,
oversized/interrupted/noncanonical records, altered hashes, and projection or
receipt copies that disagree with canonical replay. It hashes the same bytes
that it semantically replays, on the same file descriptors.

This format is **unsigned** and reports `external_custody: false`. A party able
to rewrite the whole bundle can recompute all hashes. Signatures, independent
witnessing, best-effort writer-outage reconciliation, historical-custody
migration, managed authorization and the remaining durability gates stay open.

## Validation

| Layer | Result | Scope |
|---|---|---|
| Local macOS ledger suite | 136 passed; zero failures or ignored tests | Linux launch suite excluded |
| Native VPS ledger suite | 157 passed; zero failures, ignored tests or skips | Exact committed archive, optimized build, `OURO_CONFORMANCE=1` |
| Real Linux launch suite | 20 passed | New test covers both `tool` and `none`, selected truncated captures, embedded receipts, offline verification after deleting the store, and tampering refusal |
| Additional native smoke | Two actual launches passed | Full portable bundles and run/verification reports retained below |
| Linux-to-macOS portability | Both bundles passed offline verification | Reports exactly match Linux; no native macOS execution claim |
| Clippy, formatting, schemas, links, I02 and Jail freeze | Passed locally | No Cargo.lock or frozen Jail input changes |
| Raspberry Pi | SSH connection timed out | No fresh ARM64 Linux result |

Nine new unit tests cover exact bytes, conservative labels, explicit capture
selection, retention pins, changed projection/receipt metadata, recomputed
inventories over broken canonical history, unsafe/missing/oversized members,
publication cleanup/no-overwrite, multi-page snapshots excluding later appends,
and rotation/capture-expiry/history-pruning boundaries. The new local CLI test
moves a bundle and deletes its source store before invoking the offline command.
Schema fixtures were captured from an actual CLI over a synthetic prepared run;
they are document-contract fixtures, not containment evidence.

The VPS had about 0.8 GiB free during validation; builds and all tests completed
successfully without removing unrelated data or interrupting the existing CI
run. No physical disk-full or power-loss experiment is claimed.

## Inspectable bundles

- [Protected run manifest](linux/portable-smoke/tool/bundle.json),
  [canonical records](linux/portable-smoke/tool/events.ndjson),
  [receipts](linux/portable-smoke/tool/receipts.json), and
  [Linux verification](linux/portable-smoke/tool-verified.json).
- [Unprotected run manifest](linux/portable-smoke/none/bundle.json),
  [canonical records](linux/portable-smoke/none/events.ndjson),
  [receipts](linux/portable-smoke/none/receipts.json), and
  [Linux verification](linux/portable-smoke/none-verified.json).
- [macOS verification of the protected bundle](local/tool-cross-platform-verified.json)
  and [unprotected bundle](local/none-cross-platform-verified.json).

Both commands emitted eleven stdout bytes and eleven stderr bytes. Each run
captured four bytes per selected stream and recorded truncation. The bundle
explicitly includes only stdout (`stdo`), while retaining both streams' original
metadata. The source writer was stopped and the source store deleted before
verification. The [smoke script](linux/portable-smoke.sh) records the procedure.

From the repository root, independently repeat offline verification:

```sh
cargo +1.98.1 run -q -p ouro-ledger -- verify-bundle \
  docs/specs/ledger-v1/evidence/2026-10-06-portable-bundles/linux/portable-smoke/tool --json
cargo +1.98.1 run -q -p ouro-ledger -- verify-bundle \
  docs/specs/ledger-v1/evidence/2026-10-06-portable-bundles/linux/portable-smoke/none --json
```

The manifests and these tests prove local consistency and the stated tested
behaviors. They do not establish an independent signer, external custody,
production readiness, or completion of ledger milestone 2.
