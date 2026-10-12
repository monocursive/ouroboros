# Reusing these results

The finalized original and first-after roots stay at `../../competitors` and
`../../competitors-after/2026-10-11` respectively. The latest source baseline is ac1263a. The earlier
first-after binaries were compiled before that source was committed; their
embedded old revision remains visible. Baseline source hashes are checked against
Git, and retained binary hashes match the first-after artifacts.

## Offline analysis

Run from the repository root with Python 3; no API calls are made:

```sh
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/select_startup.py docs/benchmarks/competitors-startup/2026-10-12/results
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/compare_paired.py docs/benchmarks/competitors-startup/2026-10-12/results --out docs/benchmarks/competitors-startup/2026-10-12/analysis/paired
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/verify_startup.py docs/benchmarks/competitors-startup/2026-10-12
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/finalize_saved_evidence.py docs/benchmarks/competitors-startup/2026-10-12
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/verify_frozen_inputs.py docs/benchmarks/competitors-startup/2026-10-12
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/compare_history.py docs/benchmarks/competitors-startup/2026-10-12
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/render_performance_tables.py docs/benchmarks/competitors-startup/2026-10-12
python3 docs/benchmarks/competitors-startup/2026-10-12/harness/build_startup_report.py docs/benchmarks/competitors-startup/2026-10-12
```

Verification expects the final source files in the working tree. It compares all
exported hashes, journal references, source/build manifests, receipt policies,
coverage, safety checks and old/new coding observation. CSV and JSON outputs can
also be consumed independently. Credential audits require access to the private
credential files on the three hosts; their values are never saved or printed.

SHA256SUMS covers saved files except itself. The bundle manifest separately binds
the archive and counts. Export manifests retain original and sanitized hashes
when redaction changes a file. Host archives can be unpacked with Python tarfile
using `filter="data"`; import_archive.py rejects absolute/traversal paths and
checks every exported hash. Existing changed files are preserved under
import-history rather than silently discarded.

## Running the protocol again

Use a new owned directory for every rerun. The scripts refuse to overwrite
completed raw evidence. Each host's installed-harness snapshot is the exact
harness used there; Linux final native scripts target `~/bench-ouro-startup-stable-final`; retained
container controls target `~/bench-ouro-startup-final`, while
Mac controls target `~/bench-ouro-startup`. Adapt that root to a new empty path,
retain the same frozen tools/client bytes, policies, inputs, models, tasks, limits,
30 samples, three warmups and seed 20261011. Keep native and container lifecycles
separate. Finish compilation, tests and diagnostic profiling before timings on
the same machine. Interleave old/new binaries in each seeded round.

The private keys, OAuth cache, proxy database and OpenShell CA keys are not in
public artifacts. Restore/provision private login/provider state outside the
repository; authentication was already authorized for the test hosts. The
optional stopped VPS original working-state backup is private, outside Git, and
has restoration instructions in analysis/vps-space-recovery.json. Recreating
public results does not require publishing it.

Retained images are identified by complete IDs. VPS client images were absent
and are reconstructed from the existing frozen base and the saved recipe; Docker
and OpenShell always share one image. Source patches apply to ac1263a, with Rust
1.98.1 and the retained Cargo.lock. Do not upgrade competitors, change filesystem
semantics, suppress failures, switch models, retry only failed scored cells or
relax an observer requirement and call it the same benchmark.

Candidates/v3 and candidates/v4 plus their archives retain withdrawn native
candidate data. Final Linux container sources live in
results/{vps,pi}/container-control-export with the full original export manifests
and exact installed harness; these controls execute no Ouro binary. These native candidates are
excluded from final selection. Initial Pi diagnostics deliberately compare
truncate/overwrite/fresh semantics and retain instrumentation sources; they are
not scored workload replacements. Pi broader-suite failures are retained with
baseline comparisons and unchanged assertions; they are not a release-readiness
pass. The actual pinned reference-host job and a new release freeze remain
separate work.

## Saved source snapshot

archives/source-final.tar.gz contains all tracked workspace build/test sources
from ac1263a with the five final files overlaid. Bulky competitor artifact roots and historical benchmark results are excluded;
all build/test source files and the release-preview-2026-10-10 test fixture remain.
Original competitor results are preserved separately. analysis/source-archive.json verifies every
member and records the original source baseline and build environment. The
earlier source-v1.tar.gz is candidate input, not the final source snapshot.

Extract the final snapshot into an empty directory with tarfile filter="data".
Use Rust 1.98.1, --locked, --release, OURO_BUILD_REVISION=ac1263a0961d5e676c2a03e516848a9fd00dde9b
and OURO_BUILD_DIRTY=true for the same benchmark build metadata. This is a
benchmark reproduction snapshot, not signed release provenance.

Final source selection combines guarded Ouro client runs with unchanged v5
native competitors in native-control-export. The entire interleaved performance
suite is fresh. --only-mode ouro preserves the full seeded schedule before
filtering execution; no task, model, turn cap, hidden check or failed-call score
is changed. Exact installed harness snapshots record this selection.
