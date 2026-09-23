# J2: Linux authority

Implemented on the named x86-64 Linux lane, 2026-09-22. The lane uses
bubblewrap 0.11.1 and the unprivileged `ouro-ci` account. Live evidence is
committed under [`evidence/`](evidence/):

- [`j2-doctor-2026-09-22-ouro-ci.json`](evidence/j2-doctor-2026-09-22-ouro-ci.json):
  `doctor --json` inside the delegated user scope, all 14 pinned rows.
- [`j2-test-log-2026-09-22-ouro-ci.txt`](evidence/j2-test-log-2026-09-22-ouro-ci.txt):
  the full conformance suite, run `20260922T165552Z-e89a3f7918c2` (PASS):
  183 jail library tests, 21 J1 tests, 10 J2 tests, 36 Linux mechanism tests,
  40 review regressions, both observer suites and the remaining workspace
  tests. The run name identifies the base revision; the driver copied the
  working-tree J2 sources, including every change listed under
  [Review fixes](#review-fixes). Its remote run directory was removed.
- [`j2-host-manifest-2026-09-22-ouro-ci.txt`](evidence/j2-host-manifest-2026-09-22-ouro-ci.txt):
  the host as measured for that run.
- [`j2-no-delegation-2026-09-22-ouro-ci.md`](evidence/j2-no-delegation-2026-09-22-ouro-ci.md):
  both observation modes from an ordinary, nondelegated SSH session.

The doctor report, test log and host manifest come from that one run of the
fixed tree. The nondelegated measurement predates the review fixes; in
particular its preferred-default receipts predate the unenforced-ceiling
reason and wrapper note, which so far have unit-test coverage only.

A later full [J3 conformance run](evidence/j3-test-log-2026-09-23-review-fixes-ouro-ci.txt),
`20260923T123309Z-8a5ab780e283` (PASS), verifies the J2 follow-up: a real
io_uring ring passed as stdio refuses before target execution with
`invalid_fd`. The run copied the working-tree fixes at base revision
`8a5ab780e283`; its [doctor report](evidence/j3-doctor-2026-09-23-review-fixes-ouro-ci.json)
and [host manifest](evidence/j3-host-manifest-2026-09-23-review-fixes-ouro-ci.txt)
were collected in the same delegated scope.

## Operator setup

J2 consumes an existing systemd user-service delegation. The reference account
has lingering enabled and `cpu memory pids` in its delegated service's
`cgroup.subtree_control`. A plain SSH login is outside that subtree: Linux's
common-ancestor rule prevents moving its children into the delegation.

Run the supervisor inside a transient user scope:

```sh
XDG_RUNTIME_DIR=/run/user/$(id -u) systemd-run --user --scope --quiet \
  /absolute/path/to/ouro-jail run --workspace /absolute/workspace \
  --limit pids=64 --limit mem=256MiB --limit cpu=100 -- /usr/bin/make
```

The conformance driver does this for doctor and tests. It requires a working
user manager and never silently retries outside the scope. Doctor reports a
controller usable only after configuring/read-back, fixture placement,
`cgroup.kill`, empty population, reaping and cleanup. A separate observer probe
attaches to a blocked launcher and matches a real create result and final exit.
`doctor` measures every probe; a run measures only the probes its plan's
requirements name.

Each attempt uses a fresh, identity-pinned leaf. The blocked backend bootstrap
moves into it before creating namespaces, so the child's cgroup namespace is
rooted at the leaf and `/proc/self/cgroup` reveals no host cgroup path.
Bubblewrap and namespace init are charged and explicitly listed in the receipt;
the supervisor, outside observer and lifetime watcher are excluded. The trusted
inside launcher temporarily occupies the target slot before exec. The PID
ceiling includes the two backend helper slots (a ceiling too small for setup
refuses before target execution). A missing required controller refuses; a
missing preferred controller is recorded unapplied, with the reason in the
prepared receipt's `lifetime.native.details.execution_cgroup.unavailable` and
in a wrapper note (`fields.kind = limit`) on the trace. `none` continues to
refuse pending J3.

`cpu` is percent of aggregate capacity with a 100 ms period. `mem` is written
at page granularity: the kernel keeps `memory.max` in pages, so a byte value is
rounded down to whole pages before it is written and read back, and a value
below one page refuses. Throttling and PID allocation failures set their
measured `hit` fields but do not invent a termination signal. Memory hits come
from `memory.events`; OOM is attributed only after `oom_kill` advances, in both
observation modes (with observation off the outcome's kind stays `unknown`;
its cause is still `memory_oom`). `memory.max` limits resident memory, not
swap: the OOM fixture disables swap in its own leaf to make exhaustion
deterministic. Exit 137 by itself remains an ordinary exit. Counters are
sampled every 100 ms and once more before an outcome is classified; the final
samples reach the terminal receipt and wrapper limits count, including with
observation off.

## Lifetime and filesystem

A trusted bootstrap retains the initial parent-death signal and blocks before
execing bubblewrap. A separate watcher holds live supervisor/backend pidfds and
must confirm readiness first. It kills bubblewrap if the supervisor dies during
bubblewrap's parent-death rearming window. A watcher gone while the backend
still runs causes the supervisor to stop the attempt; the watcher following
the backend out at the end of a run is not a loss. Termination uses the
namespace-init pidfd and cgroup.kill; settlement additionally requires empty
cgroup population and helper completion. An unknown tree retains scratch and
remains nonsettled.

The build profile exposes only declared inputs, with scratch writable and,
when the workspace is not granted, an empty working directory that is a tmpfs
sealed read-only once every grant beneath it is mounted, wherever its host
path lies. A read-only workspace is mounted before the writable grants inside
it, so it never covers them. The root mount is read-only. Writable grants,
read-only overlays, protected objects and denials retain their precedence.
Tool protection scans every writable root, pins all bind sources, and refuses
scan/descriptor exhaustion. The existing native x86-64 filter is also
exercised through x32 and int-0x80 compat calls.

## Acceptance map

| Gates | Evidence |
|---|---|
| F01–F04 | Existing `conformance_j1`, `review_linux`, filesystem mechanism/unit tests; J2 build-input fixture |
| S01–S02 | Live raw-syscall baseline, namespace/mount families, glibc clone3 fallback and AF_UNIX fixtures in `linux_mechanisms`/`conformance_j1` |
| S04 | Denied io_uring setup/enter/register through native, x32 and compat ABIs; descriptor closure fixtures; inherited io_uring stdio refusal |
| X02–X06 | Portable/live gate fault suites, owner handoff and descriptor/argv/environment regressions; bounded stalled-backend argument delivery |
| L01 | Wall, signal, descendant and fork-storm fixtures, BOOTTIME clock tests |
| L02 | Kill supervisor and every runtime process helper with observation on/off; synchronized bootstrap death before release and after PDEATHSIG clearing |
| L03 | Required/preferred controller absence, real delegated subtree without pids, explicit same-value pids, observation on/off, pre-release membership/read-back |
| L04 | Aggregate fork ceiling, actual CPU throttling, resident-memory OOM and ordinary exit-137 discrimination |
| L05 | Portable platform simulation returns unknown tree despite known target exit; scratch retained and no settlement |

Subprocess-helper tests marked ignored are invoked explicitly by their owning
test. They are not skipped acceptance checks.

## Review fixes

Landed after the first J2 measurement and measured live by run
`20260922T165552Z-e89a3f7918c2`:

- Memory ceilings are written at page granularity (rounded down; below one
  page refuses), so the read-back check no longer fails a byte value the
  kernel rounds and a preferred ceiling no longer silently loses the leaf.
- An OOM kill is attributed as `outcome.cause = memory_oom` with observation
  off as well; only the outcome's kind stays `unknown` there.
- A read-only workspace is mounted before the writable grants inside it.
- An ungranted build workspace is an empty tmpfs sealed read-only after every
  grant beneath it, wherever its host path lies; a scratch at `/tmp` no longer
  hides or absorbs it.
- Only a watcher gone while the backend still runs is a lost helper; the
  watcher following the backend out no longer hard-kills a finished tree.
- Leaf removal is by name in the pinned parent directory, after the identity
  check.
- A preferred ceiling that runs unenforced records why, in the prepared
  receipt's native details and a wrapper note.
- A run measures only the probes its requirements name; `doctor` measures all
  14. Counters are sampled every 100 ms and once more before an outcome is
  classified. A backend bootstrap that cannot exec bubblewrap reports the
  reason through the status pipe, so the refusal carries it.
- Tests: the mechanism suite derives its cgroup-row expectation from the
  session's delegation facts and fails outside the scope only under
  `OURO_CONFORMANCE=1`; the build fixture asserts the working directory is
  read-only; the OOM fixture covers both observation modes; the mount table
  has unit tests for the read-only and ungranted workspace shapes.

ARM64 execution, nested agent execution, network mediation, credential staging and uncontained execution have
their separately scheduled lanes/milestones.
