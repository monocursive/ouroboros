# Cross-run queries and event-count comparison, 2026-10-06

Implementation: `a2b92094a07c908dd272b26023743e0a3425534b` on `dev`.
The final tested source is `eb84b9ec3db5a0be8efd9a777835aff64995a8ab`, which
additionally refuses comparison when run-wide coverage is unobserved even if an
individual class claims active coverage. The evidence commit follows it.

## Behavior and limits

- `query --run A --run B --execs --json` returns independently bounded pages
  for up to eight explicit runs. Each preserves its snapshot, coverage, child
  protection, stage and original provenance. Use `--resume RUN=POSITION` for
  each unfinished run; a selected run without a position starts a fresh snapshot.
  Single-run output and `--cursor` remain compatible.
- `diff A B --json` compares event counts by class, source, operation, stage,
  decision and source outcome. It retains each side's protection and coverage;
  missing, active, degraded, unsupported or inconsistent evidence is explicitly
  incomparable. Audit and proxy network classes stay separate. Changes carry
  the first contributing canonical sequence and original provenance per side.
- `diff --limit` and `--after` paginate output. Continuation binds the ordered
  runs and their heads; every invocation rereads both snapshots and rejects a
  changed head. Corruption, missing history and exhausted budgets produce an
  explicit failure, never a successful empty comparison.
- Reads are capped at 64 MiB and 4,096 pages per side, with a 120-second budget
  checked between socket calls. There are at most 4,096 count keys and 8 MiB of
  key bytes per side, at most 8 KiB per key, and at most 128 KiB of serialized
  change objects per output page.

Snapshots are independent, not atomic across runs. Count equality does not
establish equal paths, hosts, field values, event order or behavior. Owner and
operator assertions and wrapper receipt notes are outside count comparison.
The first-record references are examples, not exhaustive occurrence lists.
These are local evidence queries, not external custody or managed authorization.
Implicit all-run selection, catalog filters and entity-level comparison remain
open, alongside bundles, outage reconciliation and the wider milestone-2 gates.

## Validation

| Layer | Result | Scope |
|---|---|---|
| Local macOS ledger suite | 113 passed; zero failures or ignored tests | Linux launch tests are excluded on macOS |
| Final native VPS ledger suite | 131 passed; zero failures, ignored tests or skips | Optimized build, all 17 actual Linux launch tests, `OURO_CONFORMANCE=1` |
| New comparison unit tests | 4 passed in both suites | Source separation, stage/outcome keys, contradictory coverage, budgets and incomplete records |
| Reader CLI integration suite | 13 passed in both suites | Includes four new tests of actual CLI/socket cross-run pages, restart/retry, rebinding, paginated differences and corrupt/missing history |
| Ledger Clippy, formatting, schemas, links, I02, existing Jail freeze | Passed | No frozen Jail input changed |
| Raspberry Pi | SSH connection timed out | No ARM64 execution result claimed |

The new native launch test executes a protected shell that writes a workspace
file and then an explicit unprotected `none` run. It compares those actual
streams and checks both snapshot heads, preserved protection, an incomparable
proxy class, differing filesystem observations and canonical verification.
The existing launch suite also covers child access refusal, detached ownership,
cancellation, writer/owner loss, capture and one execution across replay.

`source.json` identifies the clean source archive and its SHA-256.
`linux/validate.sh` is the exact native runner. It uses the existing release
cache, builds Jail, fixture and ledger, runs `doctor`, and executes the complete
ledger test suite in the provisioned Ubuntu user's systemd scope.
The native source and binary hashes, test log and zero completion status are saved
alongside it. The before/after native source check passes for every inventoried file. `macos/validation.json`, `macos/source.sha256`, the test log and
`macos/checks.log` bind local validation to the same runtime source.

The tested Jail freeze remains at `2dd1c3b4`, with input digest
`sha256:d5a0e965cfba1184b72d88370771812dd9544d31a52316bec75e4a4b15b881b6`.
This package validation does not claim a new full-workspace conformance run,
deployment or release readiness. Hosted CI status is tracked separately.
`pi-connection.json` records the actual connectivity failure; no host kernel,
boot or network settings were changed.
