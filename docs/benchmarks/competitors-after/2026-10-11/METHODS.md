# Before/after protocol

This follows the completed comparison in `../../competitors/METHODS.md` with
the same machines, client/product versions, models, task fixtures, policies,
independent checks, deadlines, resource probes and statistical definitions.
The original report, source snapshots, raw results and archive remain unchanged.

The original Ouro source is c364e3cb3678eb9120901f71bf3881d85e3c4911. `source.patch`
and `source-files.json` describe the final uncommitted changes. Both Linux
architectures use Rust 1.98.1 release builds. Installed binary hashes and actual
doctor reports accompany the host evidence. No benchmark disables observation,
reduces coverage, omits durable settlement or relaxes a policy to obtain success.

## Fixed work and startup attribution

The seven workloads retain their original three warmups, 30 measured samples,
reference operation counts/checksums and random seed 20261011. Workload/arm pairs
are shuffled within each round and serialized on a host. Compiler, installation,
intrusive profiling, and validation phases end before these timings begin.

Linux adds `ouro-before`, the original executable, to the original arm registry.
It runs alongside the patched `ouro-jail` with exactly the same workspace,
read-only private parent and directory-denial policy. This controls for host and
time drift; the historical October 11 medians are preserved separately. The
directory-denial profile is unchanged so the file fix does not alter the timing
comparison. The original failing regular-file case is a separate before/after
feature probe, with sibling reads, symlink access, writes, truncation and chmod.

Every scored Ouro sample must match reference work, exit zero, avoid timeout,
settle an empty process tree, and report exited outcome with no coverage gaps.
The paired analysis additionally verifies identical policy digests, observation
on with strict evidence, enforced containment, observed exec, attached ptrace
with the same linux-closed-v1 set, unchanged coverage-class statuses, and all
1,000 expected writes observed in the write workload. Observation-off remains
an excluded diagnostic.

Tables use median and nearest-rank p95. `compare_paired.py` pairs old/new samples
by host, workload and round. Its descriptive 95% intervals resample the 30
round-pair changes 10,000 times with seed 20261011. Median-of-paired changes and
ratios differ from differences/ratios of separately computed medians; the report
labels them explicitly. No multiple-comparison adjustment or population-wide
performance claim is made. Pi write variability remains in the data.

Parent-only strace is diagnostic, excluded from timing samples. It avoids
attaching to children owned by Ouro's observer. The patch shares one fresh
namespace status sandbox within a measurement call while retaining each user,
PID and network validator. Actual boundary readbacks, observer attachment,
filter verification, pinned mounts, cgroups, leases, journals and lifetime
settlement are unchanged.

## Coding tasks and configurations

Each selected host/client/wrapper cell retains six small tasks: three fixtures,
two repetitions, fresh repositories/home/state and unchanged external tests plus
hidden assertions. The inventory workflow retains one invocation per cell and
the same 15-turn Claude cap. Nonzero exit remains a failure even when a visible
patch passes tests. Agent elapsed time includes provider/model latency; it is
compatibility evidence, not a measurement of sandbox CPU cost.

Native and container classes remain separate. Each Docker/OpenShell pair uses
the same image, binaries, UID and runner. New image tags preserve earlier image
references. The current recorder also captures CSV sources; this repairs the
earlier Mac artifact omission without changing task prompts or checks. Public
host and image provenance identify package/runtime differences. Pi unavailable
warm startup is recorded separately; a failed launch never becomes a fast sample.
The unchanged offline Mac preview uses its original four shell fixtures and
three fresh VM samples each, separately from native/container rankings.

Previously authorized Codex caches and the supplied Anthropic key are reused
only on the hosts. Provider expiry metadata is set to the cache's actual expiry
before refresh configuration. Credentials are not placed in shell arguments,
images or public artifacts. Export excludes private state/config/cache files and
redacts actual credential values. Every referenced Ouro journal is retained and
checked by the export manifest.

## Exclusions and proof limits

Setup pilots remain available with their exact outputs. The Mac duplicate
provider-profile import stopped before any timed task. It is followed by a
prepared provider and a new output directory. Native Linux links that traversed
an ungranted intermediate benchmark directory produced ENOENT; those affected
client datasets are setup-invalid. Direct-to-install links restore the original
layout without changing executable bytes or widening grants. Reruns include
every mode/task/repetition for affected clients, rather than retrying individual
valid failures.

VPS validation is run serially in the repository's systemd user scope. The initial
unscoped cgroup assertion fails with both original and patched executables and
passes in that scope. The benchmark host's established AppArmor/nesting settings
differ from the pinned reference manifest; their corresponding assertion
failures are retained. Saved preview evidence rejects the changed source as
stale. This is runtime/benchmark validation, not refreshed pinned-reference
conformance, release provenance or a release-readiness claim. No assertion,
freeze record, host restriction or competitor source was modified to erase
those failures.

Temporary services belong to this run and are stopped after capture. Original
results and credentials remain on the hosts for reuse. Only recorded build
caches belonging to this follow-up were removed to recover VPS disk space after
validation, with installed binary equality checks first. No commit or push is
part of this request.

Disk recovery during the later VPS workflow phase also offloaded its own completed
source checkout: archive retained locally, all 7,893 file hashes verified before
removal. Fixed-work measurements had already ended. The private proxy store is
compressed only after native tasks and rule probes finish, hash-verified, and
kept with mode 0600 on the host. These recoveries preserve public evidence and private bytes.

This run began on October 11 and continued across local midnight into October 12.
The result directory retains its start date; per-invocation UTC timestamps record
the actual measurement times. No model or product version changed at midnight.

Later setup corrections are retained separately: Pi warm pilot names exceeded
OpenShell's 19-character limit and are excluded from availability claims; corrected
checks run after initial measured work with short names, adding warm agent cells
only if ready. The VPS Codex builder ran out of disk before tasks on a redundant
chmod layer copying large executables. That layer is omitted only after asserting
input file modes already equal a+rX; executable bytes and runtime permissions
remain identical. Only exact owned failed builder/container/image IDs are cleared.
The cleanup's first check encountered an already cascaded-away parent image;
that diagnostic is retained, and retry records absent IDs without broad pruning.

Final coding receipt verification also compares observer diagnostics to the
original selected receipts. All42 have strict observation, attached ptrace,
empty-tree settlement and no declared class gaps. Fourteen Claude receipts
retain existing audit-only path_claim_unverified entries (classes=[]), not
counted event loss. Their type matches before; counts vary with the commands
the model chose. They are retained and never described as wholly gap-free.
The840 paired timing samples contain no observer gaps.
