# Bounded catalog and filtered discovery, 2026-10-06

Implementation: `6a8c23c461e1a9e0f0f0edd72497198cb8d3f754` on `dev`.
The final native source archive is `9778444bd632625eba98422fa59b261c685df726`,
which isolates the unprotected test configuration. Runtime code is unchanged
between those commits. The evidence commit follows them.

## Behavior and limits

- `runs` now returns a bounded catalog envelope with accepted run identity,
  activity time, launch name, tags, outcome, protection, coverage and pruning
  markers. It accepts combined activity-time, launch, all-tags and outcome
  filters. Older preparations retain absent labels. `run --tag` records immutable
  operator labels; replay cannot change them or duplicate execution.
- Catalog pages default to 25 summaries, allow at most 100, and cap serialized
  summary bytes at 128 KiB. Each request scans at most 16,384 stored runs and
  refuses above that bound. Explicit readers remain available. The compatibility
  full-record socket endpoint also refuses oversized results before cloning them.
- `query --execs --launch NAME --tag blue --outcome exited` discovers runs without
  IDs and returns one bounded event page from one run per invocation. `--after`
  traverses the matching runs and their event pages. Run activity bounds use
  `--run-since` / `--run-until`; event bounds keep `--since` / `--until`.
- Positions bind normalized filters, limits, selected summaries and accepted
  heads. Restart/retry preserves unchanged selections. Matching membership or
  head changes refuse continuation; unrelated excluded runs may change.
  Per-run pages must agree with the selected catalog head. Old reader positions
  cannot be grafted onto a fresh catalog selection with a different head.
- Empty selection, pruned history and inconsistent event bytes remain distinct.
  Failed evidence reads exit nonzero and preserve their problem or page labels.
  Successful rows retain original source/stage/provenance and protection.

The catalog describes accepted writer state, not a fresh verification of disk
bytes. Run time filtering uses last accepted activity, not launch start time.
Positions are not authority or custody proofs and add no new GC pin. Event
readers retain their existing snapshot pins and expiry. There is no atomic
cross-run snapshot. Retrying the first page of a run can open a new reader token;
ordinary resumed pages preserve restart/retry behavior. Active matching appends
invalidate automatic discovery; explicit run readers can retain an older head.
Entity-level comparison, bundles and the remaining durability/custody gates are
still separate work.

## Validation

| Layer | Result | Scope |
|---|---|---|
| Local macOS ledger suite | 121 passed; zero failures or ignored tests | Linux launch suite excluded on macOS |
| Native VPS ledger suite | 140 passed; zero failures, ignored tests or skips | Exact clean archive, optimized build, all 18 real Linux launch tests with `OURO_CONFORMANCE=1` |
| Catalog unit tests | 4 passed on both platforms | Metadata, immutable identity, restart, selection binding, pruning and hard scan/legacy response bounds |
| Reader CLI integration suite | 17 passed on both platforms | Four new actual CLI/socket tests cover filters, per-run continuation, restart/retry, head changes, stale reader grafting, empty selection and corruption |
| Clippy, formatting, schemas, links, I02 and existing Jail freeze | Passed locally | Ten I02 tests; no frozen Jail input changed |
| Raspberry Pi | SSH connection timed out | No ARM64 Linux execution result claimed |

The first native run passed 139 tests and failed the new fixture's `none` run:
it shared a configuration root containing the protected run's trusted launch
profile. Jail correctly refused because an uncontained child could alter that
configuration. A separate captured-stderr reproduction proved the protected
launch and replay already passed. The fixture now uses its own empty configuration
for `none`; no runtime guard was weakened. `linux-initial/` preserves the failed
run and reproduction diagnostic. The final suite result above supersedes it.

The new native test launches a protected shell using an actual launch profile
and tags, retries the same request, and checks the workspace marker contains
exactly one write. It then queries the resulting producer observations using
those labels, and separately checks an actual `none` run remains unprotected.
The wider launch suite exercises detached ownership, cancellation, writer/owner
loss, capture, access refusal and replay.

`source.json` binds the clean source archive and SHA-256. `linux/validate.sh` is
the native runner: it builds Jail, fixture and ledger, runs doctor, then executes
the complete ledger suite with `OURO_CONFORMANCE=1` in the provisioned Ubuntu
user's systemd scope. Native logs and before/after source and binary checksums
are recorded alongside it. `macos/validation.json`, source hashes and logs bind
the local results to the implementation source. Its only difference from the
final native source is the Linux-only fixture correction. The final evidence
commit additionally links this record from the specification; that documentation
link is outside the tested archive. The checked-in catalog/discovery
schema fixtures were captured from the actual CLI over synthetic canonical
streams; schema checks do not establish runtime containment.

The Jail freeze remains at `2dd1c3b4`, with input digest
`sha256:d5a0e965cfba1184b72d88370771812dd9544d31a52316bec75e4a4b15b881b6`.
Package validation does not constitute a new full-workspace conformance run,
deployment or release. Hosted CI status is tracked separately. The Pi failure is
recorded in `pi-connection.json`; no host kernel, boot or network settings changed.
