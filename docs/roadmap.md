# Where we're taking Ouroboros

The aim is straightforward: let developers use capable agents while keeping
control of what those agents can reach. We're starting with a standalone
Linux jail that works around existing tools. Once that foundation is easier
to install and better tested, we'll build shared records and managed workers
around it.

This page describes priorities, not a delivery schedule. **Next** means work
needed for the first usable release. **Research** means a mechanism still
needs to be proved. **Later** means a planned direction with no shipped
implementation. We haven't set release dates.

## Available in the source today

The `ouro-jail` CLI runs commands on Linux x86_64 and aarch64 with file and network
policies, runtime limits, and a receipt for each attempt. It includes HTTP
and SOCKS5 TCP proxying, optional HTTP(S) credential vaulting, event journals,
`tail`, and permission proposals with `learn`.

Native Raspberry Pi validation covers the ARM64 syscall filters and observer.
Host capabilities still decide which profiles can run: the tested Pi kernel
disables memory cgroups and omits Landlock, so the corresponding required
features refuse before the command starts.

Fourteen starter launch profiles are embedded. OpenCode has recorded live
runs, but a bundled profile is not a promise that every version of that agent
works. The [compatibility records](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/agent-compatibility.md)
name the tested combinations. macOS supports inspection commands and refuses
sandboxed execution.

You can [build the jail and try a small command](https://github.com/monocursive/ouroboros/blob/dev/docs/guide.md#build-and-check-your-host)
today. The project remains pre-release; public jail packages and a Homebrew
tap are not yet available.

## Next: make the first run easier

A new user should be able to install the jail, check their host, and run a
command without having to understand the whole implementation first.

The packaging and signature-verification tools work locally. A
[clean Ubuntu 26.04.1 VM](benchmarks/jail/onboarding-2026-09-30.md), with no Rust
toolchain, completed signed installation, a sandboxed command and a real
OpenCode run in 67.32 seconds. The record names the exact build and host and
preserves the unsuccessful Ubuntu 22 and stock Ubuntu 24 attempts. This local
package test does not establish public release availability or wider support.

Before public distribution, we also need to choose the release repository,
Homebrew tap, and production signing identity. Until those are configured,
the guide uses a source build and makes the host requirements explicit.

## Next: test the workflows people will use

We need current results for real agent versions, alongside the underlying
containment tests. Each compatibility record should say which agent, version,
jail build, host, and policy were used, what worked, and what remains unknown.
A launch profile stays experimental until that combination has evidence.

Performance measurements need the same care. The
[recorded benchmark](https://github.com/monocursive/ouroboros/blob/dev/docs/benchmarks/jail/followup-2026-09-29.md#k17-results)
shows a substantial observation cost on file-heavy work. We'll keep reporting
startup and workload overhead separately, refresh the measurements against
a committed build, and add results from actual agent workflows.

The [October 1 working-tree follow-up](benchmarks/sandboxes/observation-and-limits-2026-10-01.md)
reduces read workload time from 24.53 ms to 6.10 ms on the reference VPS;
write workload cost remains high. The
[write and disk-quota follow-up](benchmarks/sandboxes/write-observation-and-disk-quotas-2026-10-01.md)
reduces paired write workload time by 3.6% and verifies ext4/XFS user hard
quotas with 41 live checks. Explicit swap and bounded tmpfs ceilings also have
live checks. The [October 2 baseline](specs/jail-v1/evidence/2026-10-02-final/README.md)
records a passing conformance run and current tested freeze. Project quotas and
automatic volume provisioning remain pending.

The release checks also include the full test suite, Linux conformance,
security review, and unresolved findings. Documentation and a successful
demo help people evaluate the tool; they do not replace those checks.

## Research: run natively on macOS

We want the same local workflow on a Mac. The current blocker is making sure
the entire process tree stops when its supervisor or privileged helper dies,
including children that have detached from their parent.

The first Endpoint Security prototype cleans up while its custodian stays alive;
killing that custodian left workloads running. A
[reciprocal-custody prototype](https://github.com/monocursive/ouroboros/blob/dev/docs/benchmarks/jail/macos-reciprocal-custody.md) now
uses two independent clients. In 200 development VM trials, either one could
fail and the surviving client cleaned up the known fixture. Killing both left
every known fixture process running, and fail-closed exec authorization did
not prevent new execution after both clients disappeared. Apple's entitlement
approval is also pending; approval alone will not fix that lifetime gap.

Native execution will stay disabled until cleanup works under normal macOS
security settings and passes the failure tests. Inspection commands remain
useful in the meantime. A future Mac client that submits work to Linux is a
separate feature from running a sandbox locally on the Mac.

## In progress: keep useful records across runs

The first local `ouro-ledger` slice now reserves attempts, durably admits them
before execution, ingests the jail's source events and records settlement.
It includes inspection, local consistency verification, orphan reconciliation,
bounded opt-in output capture, paginated evidence queries for one run, and
export of the exact canonical NDJSON records. Query results retain their
provenance and report coverage and protection separately from local consistency.
The jail still works independently.

Detached batch runs now use separate Linux user services for the writer and
launch owner. They require an already provisioned lingering user manager.
[Live lifecycle checks](specs/ledger-v1/evidence/2026-10-02-detached/README.md)
cover SSH disconnect/reconnect, duplicate submission, bounded output,
cancellation, owner death and writer loss. `wait` reads the durable outcome;
`cancel` requests a stop and leaves final settlement to the owner.

The [ledger specification](specs/ledger-v1.md) names its current acceptance and
limits. The complete milestone remains open: cross-run queries, comparisons,
retention configuration, signed bundles, best-effort recovery and managed project authorization
are still planned. A plain local export does not establish external custody.

The storage/recovery slice adds durable segment and replay anchors, a rebuildable
SQLite run index and reader cursors that survive writer restart. Canonical
segments now rotate at 64 MiB while preserving global record ordering, exact
exports and restartable reader snapshots. The
[rotation checks](specs/ledger-v1/evidence/2026-10-05-rotation/README.md) cover
interrupted rotation and damaged segments. Durable operator holds and
`gc --dry-run` now explain retention candidates while preserving active runs,
unknown outcomes and reader snapshots. Whole-run `gc` now verifies canonical
history, persists replay identities and chain anchors, then removes inventoried
segments and captures with restart recovery. The
[pruning checks](specs/ledger-v1/evidence/2026-10-05-pruning/README.md) record its
failure boundaries and platform evidence. Persistent retention configuration and
separate capture policies remain pending.

## Later: submit work to a team worker

A managed worker would let a developer submit a task to a company-controlled
Linux machine under project policy, then receive artifacts and test results
to review. The first target is one worker with a submission client, including
for developers on Macs.

The [pilot preparation record](benchmarks/managed/pilot-plan-2026-09-30.md)
names the repository, team, model-service and deployment decisions still needed,
and the implementation gates that follow the ledger prerequisites.

After the single-worker workflow is proved, multiple workers could share
and report work across a fleet. Both stages are planned. The standalone jail
does not currently provide a team service or a fleet scheduler.

## Help us make the next run better

Useful feedback is often small and specific: the command you tried, the
agent and jail versions, your OS and kernel, the relevant profile, and the
error you saw. Include a minimal reproduction and the relevant receipt fields
when you can. Review them for private paths, prompts, and credentials before
sharing; a report rarely needs your entire project or agent state.

Documentation corrections and reproducible compatibility failures are
especially helpful while installation and support are still taking shape.
An agent preparing a report should collect those details for its user to
review before posting anything.

For the full acceptance criteria, see the
[jail specification](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v2.md).
The [north star](https://github.com/monocursive/ouroboros/blob/dev/north-star.md)
and [managed-teams specification](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/managed-teams-v1.md)
cover the later work. Ouroboros will continue to run other teams' agents;
an agent loop, chat UI, vendor session protocol, and automatic merging or
deployment are outside the current plan.
