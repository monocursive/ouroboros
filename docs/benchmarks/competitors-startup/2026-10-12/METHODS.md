# Remaining startup overhead and Pi writes: protocol

The baseline is the tested source committed as
`ac1263a0961d5e676c2a03e516848a9fd00dde9b`, including the earlier file-denial fix.
The [first after report](../../competitors-after/2026-10-11/README.md) and
[original methods](../../competitors/METHODS.md) remain unchanged. The prior
on-host patched executables are copied to this run's `ouro-jail-before`; hashes
bind them to those retained binaries. Original c364e3cb results remain a separate
historical baseline, rather than being substituted for the latest code.

## Invariants and attribution

- The same three machines, installed client/product versions, models, policy
  roles, fixtures, checksums, operation counts, task prompts, hidden checks and
  deadlines are retained. No competitor source is patched or upgraded.
- Native wrappers and fresh/retained container lifecycles remain separate.
  Existing container images are reused where available, with exact IDs and
  client hashes recorded. Docker/OpenShell pairs always share an image.
- Seven fixed workloads use three discarded warmup rounds, 30 scored samples
  per available host/tool/workload bucket and seed 20261011. Old/new Ouro pairs
  are shuffled with the other arms within each round and run serially on a host.
- Every scored Ouro sample must keep observation on, strict evidence, enforced
  containment, observed exec, attached ptrace/linux-closed-v1, the same declared
  coverage statuses, no gaps, matching work and empty-tree settlement. Write
  samples must retain all 1,000 expected fs.write observations. Old/new policy
  digests must match. A failed or invalid sample remains in the raw data.
- Before/after doctor status, reason and mechanism rows, syscall canaries and
  the other safety/resource probes are compared. File denial is rechecked with
  both binaries; the baseline is already fixed and should now pass too.
- Small coding tasks retain three tasks twice per available client/mode; the
  inventory workflow retains one invocation and the Claude 15-turn limit.
  Successful exit, unchanged tests, supplied checks and hidden checks are all
  required. Model/provider elapsed time is compatibility evidence, not pure
  sandbox startup cost. Existing audit-only pathname diagnostics remain visible.

## Profiling and Pi investigation

Parent-only strace, candidate control launches and instrumented write payloads
are excluded diagnostics. Strace never attaches to children owned by Ouro's
observer. Candidate source patches, input hashes and build logs are retained.
Compiler, profiling and validation work finishes before scored Linux timings.
The independent Mac control rerun does not overlap its own compilation.

The Pi write diagnostic adds per-operation clocks to a separate C payload and
captures CPU frequency, thermal, memory, VM and block counters. A second matrix
compares truncating existing files, overwriting without truncation, and creating
fresh files on the same ext4 filesystem. All variants retain 1,000 writes and
1,024,000 bytes; their different semantics are explicit and never replace the
original scored O_TRUNC workload. No filesystem option, governor, storage device,
kernel security restriction, observer setting or durability requirement changes.

The patch avoids stat calls only for ordinary, unprotected DT_REG entries.
Protected names, directories, symlinks and unknown types retain no-follow stat;
entry/depth bounds, directory stamps, protected inode pins, re-scan after
placeholders and mount-handoff mutation checks remain. Independent namespace,
read-only and baseline-filter validators may share one fresh successful sandbox;
any unsuccessful combination falls back to the unfiltered/individual paths.
Other probes and actual boundary readbacks remain. Observer shutdown waits on
delivered events/channel closure rather than an unconditional sleep, still
draining all facts and joining for the same final account.

## Storage, credentials and proof limits

The VPS begins with about 340 MB free. Its build source/target uses an owned
directory on /dev/shm; the measured workspace, journals and runtime remain on the
original disk. A stopped original benchmark working-state archive was privately
offloaded, all 57,339 entries verified including contents, modes and links, then
the selected working directories reclaimed. Executables and login caches remain
on the VPS. The private archive is outside Git/public results, with its hash and
restoration instructions in [space recovery](analysis/vps-space-recovery.json).
Original published evidence and both earlier bundles are unchanged.

The previously authorized Anthropic key and Codex caches are reused only from
private files. New proxy/gateway state belongs to this run. Credential values,
private agent homes/configuration, proxy databases and CA private keys are
excluded or redacted during export; exact-value and archive audits precede final
packaging. Every referenced Ouro journal must be exported and hash-verified.

These are the same provisioned hosts, including the earlier VPS AppArmor/bwrap
setup and Pi Unix diagnostics module. Pi memory-controller/Landlock limitations
remain. Runtime/benchmark validation is distinct from pinned-host conformance,
release provenance and a refreshed release freeze. No expectation or restriction
is relaxed to make a test pass. Unavailable launches, model failures and setup
pilots are retained and labelled separately from successful timings.

## Final-candidate correction

Candidate v3 additionally reused a process-cached bubblewrap version in receipts.
That saves a query for short-lived CLI runs, but can report stale backend-version
data after a backend upgrade in a long-lived process. That optimization was
withdrawn. Final code retains the original fresh version readback; no persistent
capability or version evidence cache is introduced. The final scored Linux runs
use separate owned roots `~/bench-ouro-startup-native-final`. Initial v3 samples, partial
coding runs and interruption records remain in the candidate archives, excluded
from the final comparison. Mac controls continue unchanged, since this correction
affects only Linux Ouro.

The final source patch applies to ac1263a; `source-files.json` binds the exact
source files. Earlier candidate patches/hashes and parent-only profiles remain
for inspection. The two earlier finalized datasets and bundles are unchanged.

Candidate v4 kept the combined success path but shared a read-only/namespace
fallback. A read-only setup failure without fixture output could contaminate
namespace capability statuses. Final v5 restores the namespace-only fallback
and independently runs read-only/filter checks when the combination fails. Its
regression and both hosts' final native reruns use the current source hashes.
Complete v4 container controls execute no Ouro code and are reused with their
original export hashes; the complete Mac rerun is unchanged. Final selection
labels these source roots explicitly. Superseded v4 native data remains in
candidates/v4 and archives, excluded from final native results.

## Pi timing interruption retained

The first v5 Pi timing attempt recorded a baseline CPU preflight failure when
receipt persistence made no progress within the existing five-second budget.
During inspection the operator briefly sent SIGSTOP/SIGCONT to the timing runner,
then discovered that measured rows had already begun. This intervention can
contaminate the in-flight sample. The entire timing cohort was therefore retained
as excluded, including its 123 measured rows, preflight failure, receipts and
journals; it is never used for the reported latency improvement. No model calls
had begun. The entire seeded timing protocol was restarted in a fresh directory,
with unchanged binaries, policy, storage and host settings. This is a recorded
operator correction, not a selective retry of failed scored cells. Final raw data
retains results/pi/native-control-export/operator-pause.json, perf-interruption.json
and perf-after-operator-excluded/EXCLUDED.json. The persistence failure remains an
availability limitation, not a claimed storage fix.

## Final guarded hint and affected-case rerun

Final v6 admits regular-file hints only on local ext-family/tmpfs directories
whose change second predates CLOCK_REALTIME_COARSE. Recent directories, unknown
filesystems and failed filesystem/clock readbacks retain the original no-follow
stat path. This avoids treating a coalesced recent type change as a stable hint.
Directory stamps, inode pins, bounds and handoff checks remain unchanged; the
snapshot remains a bounded scan, not an atomic filesystem transaction.

Final roots are ~/bench-ouro-startup-stable-final. Every interleaved timing arm
and all Ouro client small tasks/workflows rerun there. --only-mode ouro executes
the Ouro positions from the unchanged full seeded schedule, with original
sequence numbers. All direct/Greywall/MXC client rows come unchanged from the
complete v5 native exports in results/{vps,pi}/native-control-export. These
competitors execute no Ouro code. V4 container controls and the complete Mac
controls remain unchanged. Each source and its hash are declared by final
selection; all superseded Ouro data stays in candidates and archives.

## Final unavailable and inconclusive cells

The guarded Pi Ouro Git case preflight refuses with state_write_failed after
the existing five-second persistence budget; no scored Git sample is taken for
that arm. Final selection has 4,590 valid samples in 153 available cells, with
810 strictly verified Ouro samples and 780 in 13 matched old/new comparisons.
No score or interval is invented for the missing Git arm.

The Pi detached-root safety canary returns evidence_lost/entry_abandoned and
has no heartbeat witness, so its heartbeat result is inconclusive. Tree-empty
receipt verification remains true. Before exits successfully with a witnessed
stopped heartbeat. This is a retained observation/safety-outcome difference,
not counted as an equivalent pass. Separate unscored lifetime diagnostics run
30 interleaved pairs after the benchmark, with unchanged binaries and settings;
all 60 have witnessed/stopped heartbeats, empty trees, success and no gaps. The
diagnostics do not replace the scored/safety outcome or prove equal rates.
